'use strict'

// built in node modules
const dns       = require('dns')
const net       = require('net')

const { Resolver } = require('dns').promises;
const resolver  = new Resolver();

// NPM modules
const constants = require('haraka-constants')
const net_utils = require('haraka-net-utils')
const tlds      = require('haraka-tld')

exports.register = function () {
    this.load_fcrdns_ini()

    this.register_hook('connect_init', 'initialize_fcrdns')
    this.register_hook('lookup_rdns',  'do_dns_lookups')
    this.register_hook('data',         'add_message_headers')
}

exports.load_fcrdns_ini = function () {
    const plugin = this
    plugin.cfg = plugin.config.get('fcrdns.ini', {
        booleans: [
            '-reject.no_rdns',
            '-reject.no_fcrdns',
            '-reject.invalid_tld',
            '-reject.generic_rdns',
        ]
    }, function () {
        plugin.load_fcrdns_ini()
    })

    if (isNaN(plugin.cfg.main.timeout)) {
        plugin.cfg.main.timeout = (plugin.timeout || 30) - 1;
    }
}

exports.initialize_fcrdns = function (next, connection) {
    // always init, so results.get is deterministic
    connection.results.add(this, {
        fcrdns: [],               // PTR host names that resolve to this IP
        invalid_tlds: [],         // rDNS names with invalid TLDs
        other_ips: [],            // IPs from names that didn't match
        ptr_names: [],            // Array of host names from PTR query
        ptr_multidomain: false,   // Multiple host names in different domains
        has_rdns: false,          // does IP have PTR records?
        ptr_name_has_ips: false,  // PTR host has IP address(es)
        ptr_name_to_ip: {},       // host names and their IP addresses
    })

    next()
}

exports.resolve_ptr_names = function (ptr_names, connection, next) {

    // Fetch A & AAAA records for each PTR host name
    let pending_queries = 0
    let queries_run = false

    const results = {}
    for (let i=0; i<ptr_names.length; i++) {
        const ptr_domain = ptr_names[i].toLowerCase()
        results[ptr_domain] = []

        // Make sure TLD is valid
        if (!tlds.get_organizational_domain(ptr_domain)) {
            connection.results.add(this, {fail: `valid_tld(${ptr_domain})`})
            if (!this.cfg.reject.invalid_tld) continue
            if (this.is_whitelisted(connection)) continue
            if (net_utils.is_private_ip(connection.remote.ip)) continue
            return next(constants.DENY, `client [${connection.remote.ip}] rejected; invalid TLD in rDNS (${ptr_domain})`)
        }

        queries_run = true
        connection.logdebug(this, `domain: ${ptr_domain}`)
        pending_queries++

        net_utils.get_ips_by_host(ptr_domain, (err, ips) => {
            pending_queries--

            if (err) {
                for (const e of err) {
                    switch (e.code) {
                        case dns.NODATA:
                        case dns.NOTFOUND:
                            break
                        default:
                            connection.results.add(this, {err: e.message})
                    }
                }
            }

            connection.logdebug(this, `${ptr_domain} => ${ips}`)
            results[ptr_domain] = ips

            if (pending_queries > 0) return

            if (ips.length === 0) {
                connection.results.add(this, { fail: `ptr_valid(${ptr_domain})` })
            }

            // Got all DNS results
            connection.results.add(this, {ptr_name_to_ip: results})
            this.check_fcrdns(connection, results, next)
        })
    }

    // No valid PTR
    if (!queries_run || (queries_run && pending_queries === 0)) next()
}

exports.do_dns_lookups = function (next, connection) {

    if (connection.remote.is_private) {
        connection.results.add(this, {skip: 'private_ip'})
        return next()
    }

    const rip = connection.remote.ip

    // Set-up timer
    const timer = setTimeout(() => {
        connection.results.add(this, {err: 'timeout', emit: true})
        if (!this.cfg.reject.no_rdns) return nextOnce()
        if (this.is_whitelisted(connection)) return nextOnce()
        return nextOnce(DENYSOFT, `client [${rip}] rDNS lookup timeout`)
    }, this.cfg.main.timeout * 1000)

    let called_next = 0

    function nextOnce (code, msg) {
        if (called_next) return
        called_next++
        clearTimeout(timer)
        next(code, msg)
    }

    try {
        resolver.reverse(rip).then(ptr_names => {
            connection.logdebug(this, `rdns.reverse(${rip})`)

            connection.results.add(this, {ptr_names})
            connection.results.add(this, {has_rdns: true})

            this.resolve_ptr_names(ptr_names, connection, nextOnce);
        })
    }
    catch (err) {
        this.handle_ptr_error(connection, err, nextOnce)
    }
}

exports.add_message_headers = function (next, connection) {
    const txn = connection.transaction;

    ['rDNS', 'FCrDNS', 'rDNS-OtherIPs', 'HostID' ].forEach((h) => {
        txn.remove_header(`X-Haraka-${h}`)
    })

    const fcrdns = connection.results.get('fcrdns')
    if (!fcrdns) {
        connection.results.add(this, {err: "no fcrdns results!?"})
        return next()
    }

    if (fcrdns.name && fcrdns.name.length) {
        txn.add_header('X-Haraka-rDNS', fcrdns.name.join(' '))
    }
    if (fcrdns.fcrdns && fcrdns.fcrdns.length) {
        txn.add_header('X-Haraka-FCrDNS', fcrdns.fcrdns.join(' '))
    }
    if (fcrdns.other_ips && fcrdns.other_ips.length) {
        txn.add_header('X-Haraka-rDNS-OtherIPs', fcrdns.other_ips.join(' '))
    }
    next()
}

exports.handle_ptr_error = function (connection, err, next) {
    const rip = connection.remote.ip

    switch (err.code) {
        case dns.NOTFOUND:
        case dns.NXDOMAIN:
        case dns.NODATA:
            connection.results.add(this, {fail: 'has_rdns', emit: true})
            if (!this.cfg.reject.no_rdns) return next()
            if (this.is_whitelisted((connection))) return next()
            return next(DENY, `client [${rip}] rejected; no rDNS`)
    }

    connection.results.add(this, {err: err.code})

    if (!this.cfg.reject.no_rdns) return next()
    if (this.is_whitelisted(connection)) return next()

    next(DENYSOFT, `client [${rip}] rDNS lookup error (${err})`)
}

exports.check_fcrdns = function (connection, results, next) {
    let last_domain
    for (const fdom in results) {    // mail.example.com
        if (!fdom) continue
        const org_domain = tlds.get_organizational_domain(fdom); // example.com

        // Multiple domains?
        if (last_domain && last_domain !== org_domain) {
            connection.results.add(this, {ptr_multidomain: true})
        }
        else {
            last_domain = org_domain
        }

        // FCrDNS? PTR -> (A | AAAA) 3. PTR comparison
        this.ptr_compare(results[fdom], connection, fdom)

        connection.results.add(this, {ptr_name_has_ips: true})

        if (this.is_generic_rdns(connection, fdom) &&
            this.cfg.reject.generic_rdns &&
            !this.is_whitelisted(connection)) {
            return next(DENY, `client ${fdom} [${connection.remote.ip}] rejected;` +
                ` generic rDNS, please use your ISPs SMTP relay`)
        }
    }

    this.log_summary(connection)
    this.save_auth_results(connection)

    const r = connection.results.get('fcrdns')
    if (!r) return next()
    if (r.fcrdns && r.fcrdns.length) return next()

    if (this.cfg.reject.no_fcrdns) {
        return next(DENY, 'Sorry, no FCrDNS match found')
    }
    next()
}

exports.ptr_compare = function (ip_list, connection, domain) {
    if (!ip_list || !ip_list.length) return false

    if (ip_list.includes(connection.remote.ip)) {
        connection.results.add(this, {pass: 'fcrdns' })
        connection.results.push(this, {fcrdns: domain})
        return true
    }

    const ip_list_v4 = ip_list.filter(net.isIPv4)
    if (ip_list_v4.length && net_utils.same_ipv4_network(connection.remote.ip, ip_list_v4)) {
        connection.results.add(this, {pass: 'fcrdns(net)' })
        connection.results.push(this, {fcrdns: domain})
        return true
    }

    for (const ip of ip_list) {
        connection.results.push(this, {other_ips: ip})
    }
    return false
}

exports.save_auth_results = function (connection) {
    const r = connection.results.get('fcrdns')
    if (!r) return

    if (r.fcrdns && r.fcrdns.length) {
        connection.auth_results('iprev=pass')
        return true
    }
    if (!r.has_rdns) {
        connection.auth_results('iprev=permerror')
        return false
    }
    if (r.err.length) {
        connection.auth_results('iprev=temperror')
        return false
    }
    connection.auth_results('iprev=fail')
    return false
}

exports.is_generic_rdns = function (connection, domain) {
    if (!domain) return false

    if (!net_utils.is_ip_in_str(connection.remote.ip, domain)) {
        connection.results.add(this, {pass: 'is_generic_rdns'})
        return false
    }

    connection.results.add(this, {fail: 'is_generic_rdns'})

    const orgDom = tlds.get_organizational_domain(domain)
    if (!orgDom) {
        connection.loginfo(this, `no org domain for: ${domain}`)
        return false
    }

    const host_part = domain.split('.').slice(0,orgDom.split('.').length+1)
    if (/(?:static|business)/.test(host_part)) {
        // Allow some obvious generic but static ranges
        // EHLO/HELO checks will still catch out hosts that use generic rDNS there
        connection.loginfo(this, 'allowing generic static rDNS')
        return false
    }

    return true
}

function hostNamesAsStr (list) {
    if (!list) return ''
    if (list.length > 2) return `${list.slice(0,2).join(',')}...`
    return list.join(',')
}

exports.log_summary = function (connection) {
    if (!connection) return;   // connection went away
    const r = connection.results.get('fcrdns')
    if (!r) return

    connection.loginfo(this, `ip=${connection.remote.ip} ` +
        ` rdns="${hostNamesAsStr(r.ptr_names)}" rdns_len=${r.ptr_names.length}` +
        ` fcrdns="${hostNamesAsStr(r.fcrdns)}" fcrdns_len=${r.fcrdns.length}` +
        ` other_ips_len=${r.other_ips.length} invalid_tlds=${r.invalid_tlds.length}` +
        ` generic_rdns=${((r.ptr_name_has_ips) ? 'true' : 'false')}`
    )
}

exports.is_whitelisted = function (connection) {
    // allow rdns_acccess whitelist to override
    if (!connection.notes.rdns_access) return false
    if (connection.notes.rdns_access !== 'white') return false
    return true
}
