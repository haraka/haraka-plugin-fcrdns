'use strict'

const assert = require('node:assert/strict')
const { beforeEach, describe, it } = require('node:test')

const constants = require('haraka-constants')
const tlds = require('haraka-tld')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

describe('fcrdns: validation', () => {
  beforeEach(async () => {
    await tlds.ready
    this.plugin = makePlugin('fcrdns')
    this.connection = makeConnection({ withTxn: true })
    await callHook(this.plugin, 'initialize_fcrdns', this.connection)
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
        assert.equal(
          expected,
          this.plugin.is_generic_rdns(this.connection, host),
        )
      })
    }
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

    it('exact match passes and registers results', () => {
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

    it('does NOT set ptr_name_has_ips when PTR has no IPs', () => {
      this.connection.remote.ip = '10.1.1.1'
      const results = { 'foo.example.com': [] }
      this.plugin.check_fcrdns(this.connection, results, () => {})
      assert.equal(this.connection.results.store.fcrdns.ptr_name_has_ips, false)
    })

    it('sets ptr_name_has_ips true when PTR has IPs', () => {
      this.connection.remote.ip = '10.1.1.1'
      const results = { 'foo.example.com': ['10.1.1.1'] }
      this.plugin.check_fcrdns(this.connection, results, () => {})
      assert.equal(this.connection.results.store.fcrdns.ptr_name_has_ips, true)
    })

    it('tracks generic_rdns decision separately', () => {
      this.connection.remote.ip = '188.34.255.136'
      const results = { 'dsl-188-34-255-136.asretelecom.net': ['1.2.3.4'] }
      this.plugin.check_fcrdns(this.connection, results, () => {})
      assert.equal(this.connection.results.store.fcrdns.generic_rdns, true)
    })
  })
})
