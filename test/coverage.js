const assert = require('node:assert/strict')
const dns = require('node:dns')
const { beforeEach, describe, it } = require('node:test')

const constants = require('haraka-constants')
const net_utils = require('haraka-net-utils')
const tlds = require('haraka-tld')
const {
  assertResult,
  callHook,
  makeConnection,
  makePlugin,
} = require('haraka-test-fixtures')

describe('coverage hooks', () => {
  beforeEach(async () => {
    await tlds.ready
    this.plugin = makePlugin('fcrdns')
    this.connection = makeConnection({ withTxn: true })
    await callHook(this.plugin, 'initialize_fcrdns', this.connection)
  })

  it('initialize_fcrdns seeds deterministic result keys', () => {
    this.plugin.initialize_fcrdns(() => {}, this.connection)

    const res = this.connection.results.get('fcrdns')
    assert.ok(Array.isArray(res.fcrdns))
    assert.equal(res.has_rdns, false)
    assert.equal(typeof res.ptr_name_to_ip, 'object')
  })

  it('handle_ptr_error stores err for unknown DNS failures', () => {
    const err = new Error('boom')
    err.code = 'ETIMEOUT'

    this.plugin.handle_ptr_error(this.connection, err, (rc, msg) => {
      assert.equal(rc, undefined)
      assert.equal(msg, undefined)
    })

    const res = this.connection.results.get('fcrdns')
    if (Array.isArray(res.err)) {
      assert.ok(res.err.includes('ETIMEOUT'))
      return
    }
    assert.equal(res.err, 'ETIMEOUT')
  })

  it('handle_ptr_error denies no-rdns when configured', () => {
    this.plugin.cfg.reject.no_rdns = true

    const err = new Error('missing')
    err.code = dns.NOTFOUND

    this.plugin.handle_ptr_error(this.connection, err, (rc) => {
      assert.equal(rc, constants.DENY)
    })
  })

  it('save_auth_results maps err to iprev temperror', () => {
    this.connection.results.add(this.plugin, { has_rdns: true })
    this.connection.results.add(this.plugin, { err: 'ETIMEOUT' })

    const result = this.plugin.save_auth_results(this.connection)

    assert.equal(result, false)
  })

  it('ptr_compare exact match passes', () => {
    this.connection.remote.ip = '10.1.2.3'

    const matched = this.plugin.ptr_compare(
      ['10.1.2.3'],
      this.connection,
      'mx.example.test',
    )

    assert.equal(matched, true)
    const res = this.connection.results.get('fcrdns')
    assert.ok(res.fcrdns.includes('mx.example.test'))
  })

  it('load_fcrdns_ini falls back to plugin.timeout when cfg.main.timeout is NaN', () => {
    const origGet = this.plugin.config.get.bind(this.plugin.config)
    this.plugin.timeout = 45
    this.plugin.config.get = function (...args) {
      const cfg = origGet(...args)
      cfg.main.timeout = NaN
      return cfg
    }
    try {
      this.plugin.load_fcrdns_ini()
    } finally {
      this.plugin.config.get = origGet
    }
    assert.ok(!isNaN(this.plugin.cfg.main.timeout))
    assert.equal(this.plugin.cfg.main.timeout, 45)
  })

  it('load_fcrdns_ini hot-reload callback re-initialises cfg', () => {
    const origGet = this.plugin.config.get.bind(this.plugin.config)
    let hotReloadCb
    this.plugin.config.get = function (...args) {
      if (args[0] === 'fcrdns.ini') hotReloadCb = args[2]
      return origGet(...args)
    }
    try {
      this.plugin.load_fcrdns_ini()
    } finally {
      this.plugin.config.get = origGet
    }
    assert.equal(typeof hotReloadCb, 'function')
    hotReloadCb()
    assert.ok(this.plugin.cfg)
  })

  it('do_dns_lookups skips private IPs', async () => {
    this.connection.remote.is_private = true
    await callHook(this.plugin, 'do_dns_lookups', this.connection)
    assertResult(this.connection, this.plugin, 'skip', 'private_ip')
  })

  it('resolve_ptr_names denies invalid TLD when reject.invalid_tld is true', async () => {
    this.plugin.cfg.reject.invalid_tld = true
    this.connection.remote.ip = '1.2.3.4'
    let rc, msg
    await this.plugin.resolve_ptr_names(
      ['bad.invalid'],
      this.connection,
      (r, m) => {
        rc = r
        msg = m
      },
    )
    assert.equal(rc, constants.DENY)
    assert.match(msg, /invalid TLD/)
  })

  it('resolve_ptr_names skips DENY for whitelisted connections with invalid TLD', async () => {
    this.plugin.cfg.reject.invalid_tld = true
    this.connection.remote.ip = '1.2.3.4'
    this.connection.notes.rdns_access = 'white'
    let rc
    await this.plugin.resolve_ptr_names(
      ['bad.invalid'],
      this.connection,
      (r) => {
        rc = r
      },
    )
    assert.equal(rc, undefined)
  })

  it('resolve_ptr_names skips DENY for private IPs with invalid TLD', async () => {
    this.plugin.cfg.reject.invalid_tld = true
    this.connection.remote.ip = '10.0.0.1'
    let rc
    await this.plugin.resolve_ptr_names(
      ['bad.invalid'],
      this.connection,
      (r) => {
        rc = r
      },
    )
    assert.equal(rc, undefined)
  })

  it('resolve_ptr_names records fail when forward lookup returns no IPs', async () => {
    const origGetIps = net_utils.get_ips_by_host
    net_utils.get_ips_by_host = async () => []
    try {
      await this.plugin.resolve_ptr_names(
        ['mail.example.com'],
        this.connection,
        () => {},
      )
    } finally {
      net_utils.get_ips_by_host = origGetIps
    }
    assertResult(this.connection, this.plugin, 'fail', /ptr_valid/)
  })

  it('do_dns_lookups catch block calls handle_ptr_error on resolver failure', async () => {
    const dnsPromises = require('node:dns').promises
    const origReverse = dnsPromises.Resolver.prototype.reverse
    dnsPromises.Resolver.prototype.reverse = async () => {
      throw Object.assign(new Error('nxdomain'), { code: 'ENOTFOUND' })
    }
    try {
      const { rc } = await callHook(
        this.plugin,
        'do_dns_lookups',
        this.connection,
      )
      assert.equal(rc, undefined) // reject.no_rdns is false by default
    } finally {
      dnsPromises.Resolver.prototype.reverse = origReverse
    }
  })

  it('do_dns_lookups timer fires and denies when reject.no_rdns is true', async () => {
    const dnsPromises = require('node:dns').promises
    const origReverse = dnsPromises.Resolver.prototype.reverse
    dnsPromises.Resolver.prototype.reverse = () => new Promise(() => {}) // never resolves
    this.plugin.cfg.main.timeout = 1 // timeoutMs = (1-1)*1000 = 0 → fires immediately
    this.plugin.cfg.reject.no_rdns = true
    try {
      const { rc } = await callHook(
        this.plugin,
        'do_dns_lookups',
        this.connection,
      )
      assert.equal(rc, constants.DENYSOFT)
    } finally {
      dnsPromises.Resolver.prototype.reverse = origReverse
    }
    assertResult(this.connection, this.plugin, 'err', 'timeout')
  })

  it('do_dns_lookups timer fires without deny when whitelisted', async () => {
    const dnsPromises = require('node:dns').promises
    const origReverse = dnsPromises.Resolver.prototype.reverse
    dnsPromises.Resolver.prototype.reverse = () => new Promise(() => {}) // never resolves
    this.plugin.cfg.main.timeout = 1 // timeoutMs = 0 → fires immediately
    this.plugin.cfg.reject.no_rdns = true
    this.connection.notes.rdns_access = 'white'
    try {
      const { rc } = await callHook(
        this.plugin,
        'do_dns_lookups',
        this.connection,
      )
      assert.equal(rc, undefined)
    } finally {
      dnsPromises.Resolver.prototype.reverse = origReverse
    }
  })

  it('do_dns_lookups timer fires without deny when reject.no_rdns is false', async () => {
    const dnsPromises = require('node:dns').promises
    const origReverse = dnsPromises.Resolver.prototype.reverse
    dnsPromises.Resolver.prototype.reverse = () => new Promise(() => {}) // never resolves
    this.plugin.cfg.main.timeout = 1 // timeoutMs = 0 → fires immediately
    this.plugin.cfg.reject.no_rdns = false
    try {
      const { rc } = await callHook(
        this.plugin,
        'do_dns_lookups',
        this.connection,
      )
      assert.equal(rc, undefined)
    } finally {
      dnsPromises.Resolver.prototype.reverse = origReverse
    }
    assertResult(this.connection, this.plugin, 'err', 'timeout')
  })
})
