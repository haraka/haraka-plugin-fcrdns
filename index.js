'use strict';

// build in node modules
var dns       = require('dns');

// NPM modules
var constants = require('haraka-constants');
var net_utils = require('haraka-net-utils');
var tlds      = require('haraka-tld');

exports.register = function () {
    var plugin = this;

    plugin.load_fcrdns_ini();

    plugin.register_hook('connect_init', 'initialize_fcrdns');
    plugin.register_hook('lookup_rdns',  'do_dns_lookups');
    plugin.register_hook('hook_data',    'add_message_headers');
};

exports.load_fcrdns_ini = function () {
    var plugin = this;
    plugin.cfg = plugin.config.get('connect.fcrdns.ini', {
        booleans: [
            '-reject.no_rdns',
            '-reject.no_fcrdns',
            '-reject.invalid_tld',
            '-reject.generic_rdns',
        ]
    }, function () {
        plugin.load_fcrdns_ini();
    });
};

exports.initialize_fcrdns = function (next, connection) {
    var plugin = this;

    // always init, so results.get is deterministic
    connection.results.add(plugin, {
        fcrdns: [],               // PTR host names that resolve to this IP
        invalid_tlds: [],         // rDNS names with invalid TLDs
        other_ips: [],            // IPs from names that didn't match
        ptr_names: [],            // Array of host names from PTR query
        ptr_multidomain: false,   // Multiple host names in different domains
        has_rdns: false,          // does IP have PTR records?
        ptr_name_has_ips: false,  // PTR host has IP address(es)
        ptr_name_to_ip: {},       // host names and their IP addresses
    });

    next();
};

exports.do_dns_lookups = function (next, connection) {
    var plugin = this;

    if (connection.remote.is_private) {
        connection.results.add(plugin, {skip: 'private_ip'});
        return next();
    }

    var rip = connection.remote.ip;

    var called_next = 0;
    var timer;
    var do_next = function (code, msg) {
        if (called_next) return;
        called_next++;
        clearTimeout(timer);
        return next(code, msg);
    };

    // Set-up timer
    timer = setTimeout(function () {
        connection.results.add(plugin, {err: 'timeout', emit: true});
        if (!plugin.cfg.reject.no_rdns) return do_next();
        if (plugin.is_whitelisted(connection)) return do_next();
        return do_next(DENYSOFT, 'client [' + rip + '] rDNS lookup timeout');
    }, (plugin.cfg.main.timeout || 30) * 1000);

    dns.reverse(rip, function (err, ptr_names) {
        connection.logdebug(plugin, 'rdns lookup: ' + rip);
        if (err) return plugin.handle_ptr_error(connection, err, do_next);

        connection.results.add(plugin, {ptr_names: ptr_names});
        connection.results.add(plugin, {has_rdns: true});

        // Fetch A & AAAA records for each PTR host name
        var pending_queries = 0;
        var queries_run = false;
        var results = {};
        for (var i=0; i<ptr_names.length; i++) {
            var ptr_domain = ptr_names[i].toLowerCase();
            results[ptr_domain] = [];

            // Make sure TLD is valid
            if (!tlds.get_organizational_domain(ptr_domain)) {
                connection.results.add(plugin, {fail: 'valid_tld(' + ptr_domain +')'});
                if (!plugin.cfg.reject.invalid_tld) continue;
                if (plugin.is_whitelisted(connection)) continue;
                if (net_utils.is_private_ip(rip)) continue;
                return do_next(constants.DENY, 'client [' + rip +
                        '] rejected; invalid TLD in rDNS (' + ptr_domain + ')');
            }

            queries_run = true;
            connection.logdebug(plugin, 'domain: ' + ptr_domain);
            pending_queries++;
            net_utils.get_ips_by_host(ptr_domain, function (err2, ips) {
                pending_queries--;

                if (err2) {
                    for (var e=0; e < err2.length; e++) {
                        switch (err2[e].code) {
                            case dns.NODATA:
                            case dns.NOTFOUND:
                                break;
                            default:
                                connection.results.add(plugin, {err: err2[e].message});
                        }
                    }
                }

                connection.logdebug(plugin, ptr_domain + ' => ' + ips);
                results[ptr_domain] = ips;

                if (pending_queries > 0) return;

                if (ips.length === 0) {
                    connection.results.add(plugin,
                        { fail: 'ptr_valid('+ptr_domain+')' });
                }

                // Got all DNS results
                connection.results.add(plugin, {ptr_name_to_ip: results});
                return plugin.check_fcrdns(connection, results, do_next);
            });
        }

        // No valid PTR
        if (!queries_run || (queries_run && pending_queries === 0)) {
            return do_next();
        }
    });
};

exports.add_message_headers = function (next, connection) {
    var plugin = this;
    var txn = connection.transaction;

    ['rDNS', 'FCrDNS', 'rDNS-OtherIPs', 'HostID' ].forEach(function (h) {
        txn.remove_header('X-Haraka-' + h);
    });

    var fcrdns = connection.results.get('fcrdns');
    if (!fcrdns) {
        connection.results.add(plugin, {err: "no fcrdns results!?"});
        return next();
    }

    if (fcrdns.name && fcrdns.name.length) {
        txn.add_header('X-Haraka-rDNS', fcrdns.name.join(' '));
    }
    if (fcrdns.fcrdns && fcrdns.fcrdns.length) {
        txn.add_header('X-Haraka-FCrDNS', fcrdns.fcrdns.join(' '));
    }
    if (fcrdns.other_ips && fcrdns.other_ips.length) {
        txn.add_header('X-Haraka-rDNS-OtherIPs', fcrdns.other_ips.join(' '));
    }
    return next();
};

exports.handle_ptr_error = function (connection, err, next) {
    var plugin = this;
    var rip = connection.remote.ip;

    switch (err.code) {
        case dns.NOTFOUND:
        case dns.NXDOMAIN:
            connection.results.add(plugin, {fail: 'has_rdns', emit: true});
            if (!plugin.cfg.reject.no_rdns) return next();
            if (plugin.is_whitelisted((connection))) return next();
            return next(DENY, 'client [' + rip + '] rejected; no rDNS');
    }

    connection.results.add(plugin, {err: err.code});

    if (!plugin.cfg.reject.no_rdns) return next();
    if (plugin.is_whitelisted(connection)) return next();
    return next(DENYSOFT, 'client [' + rip + '] rDNS lookup error (' + err + ')');
};

exports.check_fcrdns = function (connection, results, next) {
    var plugin = this;

    var last_domain;
    for (var fdom in results) {    // mail.example.com
        if (!fdom) continue;
        var org_domain = tlds.get_organizational_domain(fdom); // example.com

        // Multiple domains?
        if (last_domain && last_domain !== org_domain) {
            connection.results.add(plugin, {ptr_multidomain: true});
        }
        else {
            last_domain = org_domain;
        }

        // FCrDNS? PTR -> (A | AAAA) 3. PTR comparison
        plugin.ptr_compare(results[fdom], connection, fdom);

        connection.results.add(plugin, {ptr_name_has_ips: true});

        if (plugin.is_generic_rdns(connection, fdom) &&
            plugin.cfg.reject.generic_rdns &&
            !plugin.is_whitelisted(connection)) {
            return next(DENY, 'client ' + fdom + ' [' + connection.remote.ip +
                '] rejected; generic rDNS, please use your ISPs SMTP relay');
        }
    }

    plugin.log_summary(connection);
    plugin.save_auth_results(connection);

    var r = connection.results.get('fcrdns');
    if (!r) return next();
    if (r.length) return next();

    if (plugin.cfg.reject.no_fcrdns) {
        return next(DENY, 'Sorry, no FCrDNS match found');
    }
    return next();
};

exports.ptr_compare = function (ip_list, connection, domain) {
    var plugin = this;
    if (!ip_list) return false;
    if (!ip_list.length) return false;

    if (ip_list.indexOf(connection.remote.ip) !== -1) {
        connection.results.add(plugin, {pass: 'fcrdns' });
        connection.results.push(plugin, {fcrdns: domain});
        return true;
    }
    if (net_utils.same_ipv4_network(connection.remote.ip, ip_list)) {
        connection.results.add(plugin, {pass: 'fcrdns(net)' });
        connection.results.push(plugin, {fcrdns: domain});
        return true;
    }
    for (var j=0; j<ip_list.length; j++) {
        connection.results.push(plugin, {other_ips: ip_list[j]});
    }
    return false;
};

exports.save_auth_results = function (connection) {
    var r = connection.results.get('fcrdns');
    if (!r) return;
    if (r.fcrdns && r.fcrdns.length) {
        connection.auth_results('iprev=pass');
        return true;
    }
    if (!r.has_rdns) {
        connection.auth_results('iprev=permerror');
        return false;
    }
    if (r.err.length) {
        connection.auth_results('iprev=temperror');
        return false;
    }
    connection.auth_results('iprev=fail');
    return false;
};

exports.is_generic_rdns = function (connection, domain) {
    var plugin = this;
    // IP in rDNS? (Generic rDNS)
    if (!domain) return false;

    if (!net_utils.is_ip_in_str(connection.remote.ip, domain)) {
        connection.results.add(plugin, {pass: 'is_generic_rdns'});
        return false;
    }

    connection.results.add(plugin, {fail: 'is_generic_rdns'});

    var orgDom = tlds.get_organizational_domain(domain);
    if (!orgDom) {
        connection.loginfo(this, 'no org domain for: ' + domain);
        return false;
    }

    var host_part = domain.split('.').slice(0,orgDom.split('.').length+1);
    if (/(?:static|business)/.test(host_part)) {
        // Allow some obvious generic but static ranges
        // EHLO/HELO checks will still catch out hosts that use generic rDNS there
        connection.loginfo(this, 'allowing generic static rDNS');
        return false;
    }

    return true;
};

exports.log_summary = function (connection) {
    if (!connection) return;   // connection went away
    var note = connection.results.get('connect.fcrdns');
    if (!note) return;

    connection.loginfo(this, [
        'ip=' + connection.remote.ip,
        'rdns="' + ((note.ptr_names.length > 2) ? note.ptr_names.slice(0,2).join(',') + '...' : note.ptr_names.join(',')) + '"',
        'rdns_len=' + note.ptr_names.length,
        'fcrdns="' + ((note.fcrdns.length > 2) ? note.fcrdns.slice(0,2).join(',') + '...' : note.fcrdns.join(',')) + '"',
        'fcrdns_len=' + note.fcrdns.length,
        'other_ips_len=' + note.other_ips.length,
        'invalid_tlds=' + note.invalid_tlds.length,
        'generic_rdns=' + ((note.ptr_name_has_ips) ? 'true' : 'false'),
    ].join(' '));
};

exports.is_whitelisted = function (connection) {
    // allow rdns_acccess whitelist to override
    if (!connection.notes.rdns_access) return false;
    if (connection.notes.rdns_access !== 'white') return false;
    return true;
}
