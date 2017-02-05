
// node.js built-in modules
var assert   = require('assert');
var dns      = require('dns');

// npm modules
var fixtures = require('haraka-test-fixtures');

// start of tests
//    assert: https://nodejs.org/api/assert.html
//    mocha: http://mochajs.org

beforeEach(function (done) {
    this.plugin = new fixtures.plugin('fcrdns');
    this.plugin.register();
    this.connection = new fixtures.connection.createConnection();
    done();  // if a test hangs, assure you called done()
});

describe('fcrdns', function () {
    it('loads', function (done) {
        assert.ok(this.plugin);
        done();
    });
});

describe('load_fcrdns_ini', function () {
    it('loads fcrdns.ini from config/fcrdns.ini', function (done) {
        this.plugin.load_fcrdns_ini();
        assert.ok(this.plugin.cfg);
        done();
    });

    it('initializes enabled boolean', function (done) {
        this.plugin.load_fcrdns_ini();
        assert.equal(this.plugin.cfg.reject.no_rdns, false, this.plugin.cfg);
        done();
    });
});

describe('handle_ptr_error', function () {
    it('ENOTFOUND reject.no_rdns=0', function (done) {
        var err = new Error("test error");
        err.code = dns.NOTFOUND;
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(undefined, arguments[0]);
        });
        done();
    });

    it('ENOTFOUND reject.no_rdns=1', function (done) {
        var err = new Error("test error");
        err.code = dns.NOTFOUND;
        this.plugin.cfg.reject.no_rdns=1;
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(DENY, arguments[0]);
        });
        done();
    });

    it('dns.NOTFOUND reject.no_rdns=0', function (done) {
        var err = new Error("test error");
        err.code = dns.NOTFOUND;
        this.plugin.cfg.reject.no_rdns=0;
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(undefined, arguments[0]);
        });
        done();
    });

    it('dns.NOTFOUND reject.no_rdns=1', function (done) {
        var err = new Error("test error");
        err.code = dns.NOTFOUND;
        this.plugin.cfg.reject.no_rdns=1;
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(DENY, arguments[0]);
        });
        done();
    });

    it('dns.FAKE reject.no_rdns=0', function (done) {
        var err = new Error("test error");
        err.code = 'fake';
        this.plugin.cfg.reject.no_rdns=0;
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(undefined, arguments[0]);
        });
        done();
    });

    it('dns.FAKE reject.no_rdns=1', function (done) {
        var err = new Error("test error");
        err.code = 'fake';
        this.plugin.cfg.reject.no_rdns=1;
        this.plugin.handle_ptr_error(this.connection, err, function () {
            assert.equal(DENYSOFT, arguments[0]);
        });
        done();
    });
});

describe('is_generic_rdns', function () {
    it('mail.theartfarm.com', function (done) {
        this.connection.remote.ip='208.75.177.101';
        assert.equal(
            false,
            this.plugin.is_generic_rdns(this.connection, 'mail.theartfarm.com')
        );
        done();
    });

    it('dsl-188-34-255-136.asretelecom.net', function (done) {
        this.connection.remote.ip='188.34.255.136';
        assert.ok(this.plugin.is_generic_rdns(this.connection, 'dsl-188-34-255-136.asretelecom.net'));
        done();
    });
    it('c-76-121-96-159.hsd1.wa.comcast.net', function (done) {
        this.connection.remote.ip='76.121.96.159';
        assert.ok(this.plugin.is_generic_rdns(this.connection, 'c-76-121-96-159.hsd1.wa.comcast.net'));
        done();
    });
    it('c-76-121-96-159.business.wa.comcast.net', function (done) {
        this.connection.remote.ip='76.121.96.159';
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, 'c-76-121-96-159.business.wa.comcast.net'));
        done();
    });
    it('null', function (done) {
        this.connection.remote.ip='192.168.1.1';
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, null));
        done();
    });
    it('tld, com', function (done) {
        this.connection.remote.ip='192.168.1.1';
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, 'com'));
        done();
    });
    it('empty string', function (done) {
        this.connection.remote.ip='192.168.1.1';
        assert.equal(false, this.plugin.is_generic_rdns(this.connection, ''));
        done();
    });
});

describe('save_auth_results', function () {

    it('fcrdns fail', function (done) {
        this.connection.results.add(this.plugin, { pass: 'fcrdns' });
        assert.equal(false, this.plugin.save_auth_results(this.connection));
        done();
    });

    it('fcrdns pass', function (done) {
        this.connection.results.push(this.plugin, {fcrdns: 'example.com'});
        assert.equal(true, this.plugin.save_auth_results(this.connection));
        done();
    });
});

describe('ptr_compare', function () {

    it('fail', function (done) {
        this.connection.remote.ip = '10.1.1.1';
        var iplist = ['10.0.1.1'];
        assert.equal(false, this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'));
        done();
    });
    it('pass exact', function (done) {
        this.connection.remote.ip = '10.1.1.1';
        var iplist = ['10.1.1.1'];
        assert.equal(true, this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'));
        done();
    });
    it('pass net', function (done) {
        this.connection.remote.ip = '10.1.1.1';
        var iplist = ['10.1.1.2'];
        assert.equal(true, this.plugin.ptr_compare(iplist, this.connection, 'foo.example.com'));
        done();
    });
});

describe('check_fcrdns', function () {

    it('fail, tolerate', function (done) {
        this.connection.remote.ip = '10.1.1.1';
        this.plugin.check_fcrdns(this.connection, ['foo.example.com'], function (rc, msg) {
            assert.equal(rc, undefined);
            done();
        });
    });

    it('null host', function (done) {
        // this result was experienced "in the wild"
        this.connection.remote.ip = '10.1.1.1';
        this.plugin.check_fcrdns(this.connection, ['foo.example.com','', null], function (rc, msg) {
            assert.equal(rc, undefined);
            done();
        });
    });
});

describe('do_dns_lookups', function () {

    it('performs a rdns lookup', function (done) {

        this.connection.remote.ip = '8.8.4.4';
        var conn = this.connection;

        this.plugin.do_dns_lookups(function (rc, msg) {
            assert.ok( /google.com/.test(conn.results.get('fcrdns').fcrdns[0]));
            assert.equal(rc, undefined);
            assert.equal(msg, undefined);
            done();
        },
        this.connection);
    });
});
