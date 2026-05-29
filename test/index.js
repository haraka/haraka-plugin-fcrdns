const assert = require('node:assert/strict')
const dns = require('node:dns')
const { beforeEach, describe, it } = require('node:test')

const constants = require('haraka-constants')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

beforeEach(async () => {
  this.plugin = makePlugin('fcrdns')
  this.connection = makeConnection({ withTxn: true })
  await callHook(this.plugin, 'initialize_fcrdns', this.connection)
})

describe('fcrdns', () => {
  it('loads', () => {
    assert.ok(this.plugin)
  })
})

describe('load_fcrdns_ini', () => {
  it('loads fcrdns.ini from config/fcrdns.ini', () => {
    this.plugin.load_fcrdns_ini()
    assert.ok(this.plugin.cfg)
  })

  it('initializes enabled boolean', () => {
    this.plugin.load_fcrdns_ini()
    assert.equal(this.plugin.cfg.reject.no_rdns, false, this.plugin.cfg)
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
})

describe('is_generic_rdns', () => {
  for (const [ip, host, expected] of [
    ['66.128.51.165', 'mail.theartfarm.com', false],
    ['188.34.255.136', 'dsl-188-34-255-136.asretelecom.net', true],
    ['76.121.96.159', 'c-76-121-96-159.hsd1.wa.comcast.net', true],
    ['76.121.96.159', 'c-76-121-96-159.business.wa.comcast.net', false],
    ['192.168.1.1', null, false],
    ['192.168.1.1', 'com', false],
    ['192.168.1.1', '', false],
    ['192.168.1.1', '192.168.1.1', false],
  ]) {
    it(String(host), () => {
      this.connection.remote.ip = ip
      assert.equal(expected, this.plugin.is_generic_rdns(this.connection, host))
    })
  }
})

describe('save_auth_results', () => {
  it('fcrdns fail', () => {
    this.connection.results.add(this.plugin, { pass: 'fcrdns' })
    assert.equal(false, this.plugin.save_auth_results(this.connection))
  })

  it('fcrdns pass', () => {
    this.connection.results.push(this.plugin, { fcrdns: 'example.com' })
    assert.equal(true, this.plugin.save_auth_results(this.connection))
  })

  it('iprev=fail when rdns but no fcrdns match', () => {
    this.connection.results.add(this.plugin, { has_rdns: true })
    assert.equal(false, this.plugin.save_auth_results(this.connection))
  })
})

describe('ptr_compare', () => {
  it('fail', () => {
    this.connection.remote.ip = '10.1.1.1'
    const iplist = ['10.0.1.1']
    assert.equal(
      false,
      this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'),
    )
  })

  it('pass exact', () => {
    this.connection.remote.ip = '10.1.1.1'
    const iplist = ['10.1.1.1']
    assert.equal(
      true,
      this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'),
    )
  })

  it('pass net', () => {
    this.connection.remote.ip = '10.1.1.1'
    const iplist = ['10.1.1.2']
    assert.equal(
      true,
      this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'),
    )
  })
})

describe('check_fcrdns', () => {
  it('fail, tolerate', () => {
    this.connection.remote.ip = '10.1.1.1'
    const results = { 'foo.example.com': [] }
    this.plugin.check_fcrdns(this.connection, results, (rc, msg) => {
      assert.equal(rc, undefined)
      assert.equal(msg, undefined)
    })
  })

  it('null host', () => {
    this.connection.remote.ip = '10.1.1.1'
    const results = { 'foo.example.com': ['', null] }
    this.plugin.check_fcrdns(this.connection, results, (rc, msg) => {
      assert.equal(rc, undefined)
      assert.equal(msg, undefined)
    })
  })

  it('denies generic_rdns when configured', () => {
    this.connection.remote.ip = '188.34.255.136'
    this.plugin.cfg.reject.generic_rdns = true
    const results = { 'dsl-188-34-255-136.asretelecom.net': [] }
    this.plugin.check_fcrdns(this.connection, results, (rc, msg) => {
      assert.equal(rc, constants.DENY)
      assert.ok(/generic rDNS/.test(msg))
    })
  })

  it('denies no_fcrdns when configured', () => {
    this.connection.remote.ip = '10.1.1.1'
    this.plugin.cfg.reject.no_fcrdns = true
    const results = { 'mail.example.com': ['10.2.2.3'] }
    this.plugin.check_fcrdns(this.connection, results, (rc, msg) => {
      assert.equal(rc, constants.DENY)
      assert.equal(msg, 'Sorry, no FCrDNS match found')
    })
  })

  it('detects ptr_multidomain', () => {
    this.connection.remote.ip = '10.1.1.1'
    const results = {
      'mail.example.com': ['10.1.1.1'],
      'smtp.other.net': ['10.1.1.1'],
    }
    this.plugin.check_fcrdns(this.connection, results, () => {})
    assert.equal(this.connection.results.store.fcrdns.ptr_multidomain, true)
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
})

describe('add_message_headers', () => {
  it('handles missing fcrdns results', () => {
    const conn = makeConnection({ withTxn: true })
    this.plugin.add_message_headers((rc) => assert.equal(rc, undefined), conn)
  })

  it('removes message headers', () => {
    this.connection.transaction.add_header('X-Haraka-FCrDNS', 'example.com')
    this.connection.transaction.add_header('X-Haraka-rDNS-OtherIPs', '1.2.3.4')

    this.plugin.add_message_headers((rc, msg) => {
      const fcrdns = this.connection.transaction.header.get('X-Haraka-FCrDNS')
      const other_ips = this.connection.transaction.header.get(
        'X-Haraka-rDNS-OtherIPs',
      )
      assert.equal(fcrdns, '')
      assert.equal(other_ips, '')
      assert.equal(rc, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('adds message headers', () => {
    this.connection.results.push('fcrdns', { fcrdns: 'mail.example.com' })
    this.connection.results.push('fcrdns', { fcrdns: 'example.com' })
    this.connection.results.push('fcrdns', { other_ips: '1.2.3.4' })

    this.plugin.add_message_headers((rc, msg) => {
      const fcrdns = this.connection.transaction.header.get('X-Haraka-FCrDNS')
      const other_ips = this.connection.transaction.header.get(
        'X-Haraka-rDNS-OtherIPs',
      )
      assert.equal(fcrdns, 'mail.example.com example.com')
      assert.equal(other_ips, '1.2.3.4')
      assert.equal(rc, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })
})
