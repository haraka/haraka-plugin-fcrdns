// node.js built-ins
const assert = require('assert')
const dns = require('dns')

// npm modules
const fixtures = require('haraka-test-fixtures')

beforeEach(function (done) {
  this.plugin = new fixtures.plugin('fcrdns')
  this.plugin.register()
  this.connection = new fixtures.connection.createConnection()
  this.plugin.initialize_fcrdns(done, this.connection)
})

describe('fcrdns', function () {
  it('loads', function () {
    assert.ok(this.plugin)
  })
})

describe('load_fcrdns_ini', function () {
  it('loads fcrdns.ini from config/fcrdns.ini', function () {
    this.plugin.load_fcrdns_ini()
    assert.ok(this.plugin.cfg)
  })

  it('initializes enabled boolean', function () {
    this.plugin.load_fcrdns_ini()
    assert.equal(this.plugin.cfg.reject.no_rdns, false, this.plugin.cfg)
  })
})

describe('handle_ptr_error', function () {
  it('ENOTFOUND reject.no_rdns=0', function (done) {
    const err = new Error('test error')
    err.code = dns.NOTFOUND
    this.plugin.handle_ptr_error(this.connection, err, function () {
      assert.equal(undefined, arguments[0])
      done()
    })
  })

  it('ENOTFOUND reject.no_rdns=1', function (done) {
    const err = new Error('test error')
    err.code = dns.NOTFOUND
    this.plugin.cfg.reject.no_rdns = 1
    this.plugin.handle_ptr_error(this.connection, err, function () {
      assert.equal(DENY, arguments[0])
      done()
    })
  })

  it('dns.NOTFOUND reject.no_rdns=0', function (done) {
    const err = new Error('test error')
    err.code = dns.NOTFOUND
    this.plugin.cfg.reject.no_rdns = 0
    this.plugin.handle_ptr_error(this.connection, err, function () {
      assert.equal(undefined, arguments[0])
    })
    done()
  })

  it('dns.NOTFOUND reject.no_rdns=1', function (done) {
    const err = new Error('test error')
    err.code = dns.NOTFOUND
    this.plugin.cfg.reject.no_rdns = 1
    this.plugin.handle_ptr_error(this.connection, err, function () {
      assert.equal(DENY, arguments[0])
      done()
    })
  })

  it('dns.FAKE reject.no_rdns=0', function (done) {
    const err = new Error('test error')
    err.code = 'fake'
    this.plugin.cfg.reject.no_rdns = 0
    this.plugin.handle_ptr_error(this.connection, err, function () {
      assert.equal(undefined, arguments[0])
    })
    done()
  })

  it('dns.FAKE reject.no_rdns=1', function (done) {
    const err = new Error('test error')
    err.code = 'fake'
    this.plugin.cfg.reject.no_rdns = 1
    this.plugin.handle_ptr_error(this.connection, err, function () {
      assert.equal(DENYSOFT, arguments[0])
      done()
    })
  })
})

describe('is_generic_rdns', function () {
  it('mail.theartfarm.com', function (done) {
    this.connection.remote.ip = '66.128.51.165'
    assert.equal(
      false,
      this.plugin.is_generic_rdns(this.connection, 'mail.theartfarm.com'),
    )
    done()
  })

  it('dsl-188-34-255-136.asretelecom.net', function (done) {
    this.connection.remote.ip = '188.34.255.136'
    assert.ok(
      this.plugin.is_generic_rdns(
        this.connection,
        'dsl-188-34-255-136.asretelecom.net',
      ),
    )
    done()
  })

  it('c-76-121-96-159.hsd1.wa.comcast.net', function (done) {
    this.connection.remote.ip = '76.121.96.159'
    assert.ok(
      this.plugin.is_generic_rdns(
        this.connection,
        'c-76-121-96-159.hsd1.wa.comcast.net',
      ),
    )
    done()
  })

  it('c-76-121-96-159.business.wa.comcast.net', function (done) {
    this.connection.remote.ip = '76.121.96.159'
    assert.equal(
      false,
      this.plugin.is_generic_rdns(
        this.connection,
        'c-76-121-96-159.business.wa.comcast.net',
      ),
    )
    done()
  })
  it('null', function (done) {
    this.connection.remote.ip = '192.168.1.1'
    assert.equal(false, this.plugin.is_generic_rdns(this.connection, null))
    done()
  })
  it('tld, com', function (done) {
    this.connection.remote.ip = '192.168.1.1'
    assert.equal(false, this.plugin.is_generic_rdns(this.connection, 'com'))
    done()
  })
  it('empty string', function (done) {
    this.connection.remote.ip = '192.168.1.1'
    assert.equal(false, this.plugin.is_generic_rdns(this.connection, ''))
    done()
  })
})

describe('save_auth_results', function () {
  it('fcrdns fail', function () {
    this.connection.results.add(this.plugin, { pass: 'fcrdns' })
    assert.equal(false, this.plugin.save_auth_results(this.connection))
  })

  it('fcrdns pass', function () {
    this.connection.results.push(this.plugin, { fcrdns: 'example.com' })
    assert.equal(true, this.plugin.save_auth_results(this.connection))
  })
})

describe('ptr_compare', function () {
  it('fail', function () {
    this.connection.remote.ip = '10.1.1.1'
    const iplist = ['10.0.1.1']
    assert.equal(
      false,
      this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'),
    )
  })

  it('pass exact', function () {
    this.connection.remote.ip = '10.1.1.1'
    const iplist = ['10.1.1.1']
    assert.equal(
      true,
      this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'),
    )
  })

  it('pass net', function () {
    this.connection.remote.ip = '10.1.1.1'
    const iplist = ['10.1.1.2']
    assert.equal(
      true,
      this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'),
    )
  })
})

describe('check_fcrdns', function () {
  it('fail, tolerate', function (done) {
    this.connection.remote.ip = '10.1.1.1'
    const results = { 'foo.example.com': [] }
    this.plugin.check_fcrdns(this.connection, results, function (rc, msg) {
      assert.equal(rc, undefined)
      assert.equal(msg, undefined)
      done()
    })
  })

  it('null host', function (done) {
    // this result was experienced "in the wild"
    this.connection.remote.ip = '10.1.1.1'
    const results = { 'foo.example.com': ['', null] }
    this.plugin.check_fcrdns(this.connection, results, function (rc, msg) {
      assert.equal(rc, undefined)
      assert.equal(msg, undefined)
      done()
    })
  })
})

describe('resolve_ptr_names', function () {
  this.timeout(5000)

  const validCases = {
    'mail.theartfarm.com': [],
    'smtp.gmail.com': [],
  }

  for (const c in validCases) {
    it(`gets IPs for ${c}`, function (done) {
      const ptr_names = [c]
      this.plugin.resolve_ptr_names(ptr_names, this.connection, () => {
        // console.log(this.connection.results.store.fcrdns)
        assert.ok(this.connection.results.store.fcrdns.ptr_name_to_ip[c].length)
        assert.equal(
          this.connection.results.store.fcrdns.ptr_name_has_ips,
          true,
        )
        done()
      })
    })
  }

  it('ignores invalid host names', function (done) {
    const ptr_names = ['mail.invalid']
    this.plugin.resolve_ptr_names(ptr_names, this.connection, () => {
      // console.log(this.connection.results.store.fcrdns)
      assert.ok(this.connection.results.store.fcrdns.other_ips.length === 0)
      done()
    })
  })
})

describe('do_dns_lookups', function () {
  const testIps = {
    '8.8.4.4': 'dns.google',
    '2001:4860:4860::8844': 'dns.google',
    '4.2.2.2': 'level3.net',
    // '208.67.222.222': 'opendns.com',
    '1.1.1.1': 'one.one',
  }

  for (const ip of Object.keys(testIps)) {
    it(`looks up ${ip}`, function (done) {
      this.timeout(5000)

      this.connection.remote.ip = ip

      this.plugin.do_dns_lookups((rc, msg) => {
        const res = this.connection.results.get('fcrdns')
        assert.ok(new RegExp(testIps[ip]).test(res.fcrdns[0]))
        // console.log(res);
        assert.equal(rc, undefined)
        assert.equal(msg, undefined)
        done()
      }, this.connection)
    })
  }
})

describe('add_message_headers', function () {
  it('removes message headers', function (done) {
    this.connection.transaction.add_header('X-Haraka-FCrDNS', 'example.com')
    this.connection.transaction.add_header('X-Haraka-rDNS-OtherIPs', '1.2.3.4')

      this.plugin.add_message_headers((rc, msg) => {
        const fcrdns = this.connection.transaction.header.get('X-Haraka-FCrDNS')
        const other_ips = this.connection.transaction.header.get('X-Haraka-rDNS-OtherIPs')
        assert.equal(fcrdns, '')
        assert.equal(other_ips, '')
        assert.equal(rc, undefined)
        assert.equal(msg, undefined)
        done()
      }, this.connection)
  })

  it('adds message headers', function (done) {
      this.connection.results.push('fcrdns', {fcrdns: 'mail.example.com'})
      this.connection.results.push('fcrdns', {fcrdns: 'example.com'})
      this.connection.results.push('fcrdns', {other_ips: '1.2.3.4'})

      this.plugin.add_message_headers((rc, msg) => {
        const fcrdns = this.connection.transaction.header.get('X-Haraka-FCrDNS')
        const other_ips = this.connection.transaction.header.get('X-Haraka-rDNS-OtherIPs')
        assert.equal(fcrdns, 'mail.example.com example.com')
        assert.equal(other_ips, '1.2.3.4')
        assert.equal(rc, undefined)
        assert.equal(msg, undefined)
        done()
      }, this.connection)
  })
})
