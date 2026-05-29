const assert = require('node:assert/strict')
const dns = require('node:dns')
const { beforeEach, describe, it } = require('node:test')

const constants = require('haraka-constants')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

describe('coverage hooks', () => {
  beforeEach(async () => {
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
})
