'use strict'

const assert = require('node:assert/strict')
const { beforeEach, describe, it } = require('node:test')

const tlds = require('haraka-tld')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

describe('fcrdns: results & headers', () => {
  beforeEach(async () => {
    await tlds.ready
    this.plugin = makePlugin('fcrdns')
    this.connection = makeConnection({ withTxn: true })
    await callHook(this.plugin, 'initialize_fcrdns', this.connection)
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

    it('maps err to iprev temperror', () => {
      this.connection.results.add(this.plugin, { has_rdns: true })
      this.connection.results.add(this.plugin, { err: 'ETIMEOUT' })

      const result = this.plugin.save_auth_results(this.connection)

      assert.equal(result, false)
    })
  })

  describe('add_message_headers', () => {
    it('handles missing fcrdns results', () => {
      const conn = makeConnection({ withTxn: true })
      this.plugin.add_message_headers((rc) => assert.equal(rc, undefined), conn)
    })

    it('removes message headers', () => {
      this.connection.transaction.add_header('X-Haraka-FCrDNS', 'example.com')
      this.connection.transaction.add_header(
        'X-Haraka-rDNS-OtherIPs',
        '1.2.3.4',
      )

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
})
