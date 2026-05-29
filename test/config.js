'use strict'

const assert = require('node:assert/strict')
const { beforeEach, describe, it } = require('node:test')

const tlds = require('haraka-tld')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

describe('fcrdns: config & setup', () => {
  beforeEach(async () => {
    await tlds.ready
    this.plugin = makePlugin('fcrdns')
    this.connection = makeConnection({ withTxn: true })
    await callHook(this.plugin, 'initialize_fcrdns', this.connection)
  })

  it('loads', () => {
    assert.ok(this.plugin)
  })

  describe('initialize_fcrdns', () => {
    it('seeds deterministic result keys', () => {
      this.plugin.initialize_fcrdns(() => {}, this.connection)

      const res = this.connection.results.get('fcrdns')
      assert.ok(Array.isArray(res.fcrdns))
      assert.equal(res.has_rdns, false)
      assert.equal(typeof res.ptr_name_to_ip, 'object')
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

    it('falls back to plugin.timeout when cfg.main.timeout is NaN', () => {
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
      assert.equal(this.plugin.cfg.main.timeout, 44)
    })

    it('hot-reload callback re-initialises cfg', () => {
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
  })
})
