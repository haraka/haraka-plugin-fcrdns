
// node.js built-ins
const assert   = require('assert')
const dns      = require('dns')

// npm modules
const fixtures = require('haraka-test-fixtures')

// start of tests
//    assert: https://nodejs.org/api/assert.html
//    mocha: http://mochajs.org

beforeEach(function (done) {
    this.plugin = new fixtures.plugin('fcrdns')
    this.plugin.register()
    this.connection = new fixtures.connection.createConnection()
    this.plugin.initialize_fcrdns(() => {
        done()
    }, this.connection)
})

describe('fcrdns', function () {
    it('loads', function (done) {
        assert.ok(this.plugin)
        done()
    })
})

describe('load_fcrdns_ini', function () {
    it('loads fcrdns.ini from config/fcrdns.ini', function (done) {
        this.plugin.load_fcrdns_ini()
        assert.ok(this.plugin.cfg)
        done()
    })

    it('initializes enabled boolean', function (done) {
        this.plugin.load_fcrdns_ini()
        assert.equal(this.plugin.cfg.reject.no_rdns, false, this.plugin.cfg)
        done()
    })
})

describe('handle_ptr_error', function () {
    it('ENOTFOUND reject.no_rdns=0', function (done) {
        const err = new Error("test error")
        err.code = dns.NOTFOUND
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(undefined, arguments[0])
        })
        done()
    })

    it('ENOTFOUND reject.no_rdns=1', function (done) {
        const err = new Error("test error")
        err.code = dns.NOTFOUND
        this.plugin.cfg.reject.no_rdns=1
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(DENY, arguments[0])
        })
        done()
    })

    it('dns.NOTFOUND reject.no_rdns=0', function (done) {
        const err = new Error("test error")
        err.code = dns.NOTFOUND
        this.plugin.cfg.reject.no_rdns=0
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(undefined, arguments[0])
        })
        done()
    })

    it('dns.NOTFOUND reject.no_rdns=1', function (done) {
        const err = new Error("test error")
        err.code = dns.NOTFOUND
        this.plugin.cfg.reject.no_rdns=1
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(DENY, arguments[0])
        })
        done()
    })

    it('dns.FAKE reject.no_rdns=0', function (done) {
        const err = new Error("test error")
        err.code = 'fake'
        this.plugin.cfg.reject.no_rdns=0
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(undefined, arguments[0])
        })
        done()
    })

    it('dns.FAKE reject.no_rdns=1', function (done) {
        const err = new Error("test error")
        err.code = 'fake'
        this.plugin.cfg.reject.no_rdns=1
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(DENYSOFT, arguments[0])
        })
        done()
    })
})

describe('is_generic_rdns', function () {

    it('mail.theartfarm.com', function (done) {
        this.connection.remote.ip='208.75.177.101'
        assert.equal(
            false,
            this.plugin.is_generic_rdns(this.connection, 'mail.theartfarm.com')
        )
        done()
    })

    it('dsl-188-34-255-136.asretelecom.net', function (done) {
        this.connection.remote.ip='188.34.255.136'
        assert.ok(this.plugin.is_generic_rdns(this.connection, 'dsl-188-34-255-136.asretelecom.net'))
        done()
    })

    it('c-76-121-96-159.hsd1.wa.comcast.net', function (done) {
        this.connection.remote.ip='76.121.96.159'
        assert.ok(this.plugin.is_generic_rdns(this.connection, 'c-76-121-96-159.hsd1.wa.comcast.net'))
        done()
    })

    it('c-76-121-96-159.business.wa.comcast.net', function (done) {
        this.connection.remote.ip='76.121.96.159'
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, 'c-76-121-96-159.business.wa.comcast.net'))
        done()
    })
    it('null', function (done) {
        this.connection.remote.ip='192.168.1.1'
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, null))
        done()
    })
    it('tld, com', function (done) {
        this.connection.remote.ip='192.168.1.1'
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, 'com'))
        done()
    })
    it('empty string', function (done) {
        this.connection.remote.ip='192.168.1.1'
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, ''))
        done()
    })
})

describe('save_auth_results', function () {

    it('fcrdns fail', function (done) {
        this.connection.results.add(this.plugin, { pass: 'fcrdns' })
        assert.equal(false, this.plugin.save_auth_results(this.connection))
        done()
    })

    it('fcrdns pass', function (done) {
        this.connection.results.push(this.plugin, {fcrdns: 'example.com'})
        assert.equal(true, this.plugin.save_auth_results(this.connection))
        done()
    })
})

describe('ptr_compare', function () {

    it('fail', function (done) {
        this.connection.remote.ip = '10.1.1.1'
        const iplist = ['10.0.1.1']
        assert.equal(false, this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'))
        done()
    })

    it('pass exact', function (done) {
        this.connection.remote.ip = '10.1.1.1'
        const iplist = ['10.1.1.1']
        assert.equal(true, this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'))
        done()
    })

    it('pass net', function (done) {
        this.connection.remote.ip = '10.1.1.1'
        const iplist = ['10.1.1.2']
        assert.equal(true, this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'))
        done()
    })
})

describe('check_fcrdns', function () {

    it('fail, tolerate', function (done) {
        this.connection.remote.ip = '10.1.1.1'
        const results = { 'foo.example.com': [ ] };
        this.plugin.check_fcrdns(this.connection, results, function (rc, msg) {
            assert.equal(rc, undefined)
            done()
        })
    })

    it('null host', function (done) {
        // this result was experienced "in the wild"
        this.connection.remote.ip = '10.1.1.1'
        const results = { 'foo.example.com': [ '', null ] }
        this.plugin.check_fcrdns(this.connection, results, function (rc, msg) {
            assert.equal(rc, undefined)
            done()
        })
    })
})

describe('do_dns_lookups', function () {

    const testIps = {
        '8.8.4.4': 'google.com',
        '2001:4860:4860::8844': 'google.com',
        '4.2.2.2': 'level3.net',
        '208.67.222.222': 'opendns.com',
        // '2001:428::1': 'qwest.net',
    }

    Object.keys(testIps).forEach((ip) => {

        it(`looks up ${ip}`, function (done) {

            const conn = this.connection
            conn.remote.ip = ip

            this.plugin.do_dns_lookups((rc, msg) => {
                const res = conn.results.get('fcrdns')
                assert.ok(new RegExp( testIps[ip] ).test(res.fcrdns[0]))
                // console.log(res);
                assert.equal(rc, undefined)
                assert.equal(msg, undefined)
                done()
            },
            conn)
        })
    })
})
