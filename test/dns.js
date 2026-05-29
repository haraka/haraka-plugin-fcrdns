'use strict'

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

describe('fcrdns: dns & ptr resolution', () => {
  beforeEach(async () => {
    await tlds.ready
    this.plugin = makePlugin('fcrdns')
    this.connection = makeConnection({ withTxn: true })
    await callHook(this.plugin, 'initialize_fcrdns', this.connection)
  })

  describe('do_dns_lookups', () => {
    const testIps = {
      '8.8.4.4': 'dns.google',
      '2001:4860:4860::8844': 'dns.google',
      '4.2.2.2': 'level3.net',
      '1.1.1.1': 'one.one',
    }

    for (const ip of Object.keys(testIps)) {
      it(`looks up ${ip}`, { timeout: 5000 }, async () => {
        this.connection.remote.ip = ip

        await new Promise((resolve) => {
          this.plugin.do_dns_lookups((rc, msg) => {
            const res = this.connection.results.get('fcrdns')
            assert.ok(new RegExp(testIps[ip]).test(res.fcrdns[0]))
            assert.equal(rc, undefined)
            assert.equal(msg, undefined)
            resolve()
          }, this.connection)
        })
      })
    }

    it('skips private IPs', async () => {
      this.connection.remote.is_private = true
      await callHook(this.plugin, 'do_dns_lookups', this.connection)
      assertResult(this.connection, this.plugin, 'skip', 'private_ip')
    })

    it('catch block calls handle_ptr_error on resolver failure', async () => {
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

    it('timer fires and denies when reject.no_rdns is true', async () => {
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

    it('timer fires without deny when whitelisted', async () => {
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

    it('timer fires without deny when reject.no_rdns is false', async () => {
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

  describe('resolve_ptr_names', () => {
    const validCases = ['mail.theartfarm.com', 'smtp.gmail.com']

    for (const c of validCases) {
      it(`gets IPs for ${c}`, { timeout: 5000 }, async () => {
        const ptr_names = [c]
        await new Promise((resolve) => {
          this.plugin.resolve_ptr_names(ptr_names, this.connection, () => {
            assert.ok(
              this.connection.results.store.fcrdns.ptr_name_to_ip[c].length,
            )
            assert.equal(
              this.connection.results.store.fcrdns.ptr_name_has_ips,
              true,
            )
            resolve()
          })
        })
      })
    }

    it('ignores invalid host names', async () => {
      const ptr_names = ['mail.invalid']
      await new Promise((resolve) => {
        this.plugin.resolve_ptr_names(ptr_names, this.connection, () => {
          assert.equal(this.connection.results.store.fcrdns.other_ips.length, 0)
          resolve()
        })
      })
    })

    it('denies invalid TLD when reject.invalid_tld is true', async () => {
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

    it('populates invalid_tlds with offending PTR names (C1)', async () => {
      this.plugin.cfg.reject.invalid_tld = false
      this.connection.remote.ip = '1.2.3.4'
      await this.plugin.resolve_ptr_names(
        ['bad.invalid'],
        this.connection,
        () => {},
      )
      assert.deepEqual(this.connection.results.store.fcrdns.invalid_tlds, [
        'bad.invalid',
      ])
    })

    it('skips DENY for whitelisted connections with invalid TLD', async () => {
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

    it('skips DENY for private IPs with invalid TLD', async () => {
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

    it('records fail when forward lookup returns no IPs', async () => {
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
  })

  describe('handle_ptr_error', () => {
    for (const [code, reject, expected] of [
      [dns.NOTFOUND, false, undefined],
      [dns.NOTFOUND, true, constants.DENY],
      ['fake', false, undefined],
      ['fake', true, constants.DENYSOFT],
    ]) {
      it(`${code} reject=${reject}`, () => {
        const err = new Error('test')
        err.code = code
        this.plugin.cfg.reject.no_rdns = reject
        this.plugin.handle_ptr_error(this.connection, err, (rc) =>
          assert.equal(rc, expected),
        )
      })
    }

    it('whitelisted skips reject', () => {
      const err = new Error('test')
      err.code = dns.NOTFOUND
      this.plugin.cfg.reject.no_rdns = true
      this.connection.notes.rdns_access = 'white'
      this.plugin.handle_ptr_error(this.connection, err, (rc) =>
        assert.equal(rc, undefined),
      )
    })

    it('stores err for unknown DNS failures', () => {
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

    it('denies no-rdns when configured', () => {
      this.plugin.cfg.reject.no_rdns = true

      const err = new Error('missing')
      err.code = dns.NOTFOUND

      this.plugin.handle_ptr_error(this.connection, err, (rc) => {
        assert.equal(rc, constants.DENY)
      })
    })
  })
})
