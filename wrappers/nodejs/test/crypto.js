
var test = require('ava')
var indy = require('../')
var cuid = require('cuid')
var initTestPool = require('./helpers/initTestPool')

test('crypto', async function (t) {
  var pool = await initTestPool()
  var walletConfig = { 'id': 'wallet-' + cuid() }
  var walletCredentials = { 'key': 'key' }
  await indy.createWallet(walletConfig, walletCredentials)
  var wh = await indy.openWallet(walletConfig, walletCredentials)

  // Create Key
  var error = await t.throws(indy.createKey(-1, {}))
  t.is(error.indyName, 'WalletInvalidHandle')

  var verkey = await indy.createKey(wh, {})
  t.is(typeof verkey, 'string')

  var seed1 = '00000000000000000000000000000My1'
  verkey = await indy.createKey(wh, { 'seed': seed1 })
  t.is(typeof verkey, 'string')

  // Sign + Verify
  var message = Buffer.from('{"reqId":1496822211362017764}', 'utf8')
  var signature = await indy.cryptoSign(wh, verkey, message)
  t.true(Buffer.isBuffer(signature))
  t.is(signature.toString('base64'), 'qdcI4QdrbgnBosrWokLu0z/RDMQI0zcbeF7MkzVoZz08+e1/Zy7c3wpfSzX10vGXvykwHgkQTvydztKRfYVtCw==')
  t.true(await indy.cryptoVerify(verkey, message, signature))
  t.false(await indy.cryptoVerify(verkey, Buffer.from('wat?', 'utf8'), signature))

  // Metadata
  await indy.setKeyMetadata(wh, verkey, 'foobar')
  var metadata = await indy.getKeyMetadata(wh, verkey)
  t.is(metadata, 'foobar')

  // Auth
  var [, stewardVerkey] = await indy.createAndStoreMyDid(wh, { seed: '000000000000000000000000Steward1' })
  var [, trusteeVerkey] = await indy.createAndStoreMyDid(wh, { seed: '000000000000000000000000Trustee1' })

  var encrypted = await indy.cryptoAuthCrypt(wh, stewardVerkey, trusteeVerkey, message)
  t.true(Buffer.isBuffer(encrypted))

  var decrypted = await indy.cryptoAuthDecrypt(wh, trusteeVerkey, encrypted)
  t.is(decrypted[0], stewardVerkey)
  t.true(Buffer.isBuffer(decrypted[1]))
  t.is(decrypted[1].toString('utf8'), message.toString('utf8'))

  // Anon
  encrypted = await indy.cryptoAnonCrypt(trusteeVerkey, message)
  t.true(Buffer.isBuffer(encrypted))

  decrypted = await indy.cryptoAnonDecrypt(wh, trusteeVerkey, encrypted)
  t.true(Buffer.isBuffer(decrypted))
  t.is(decrypted.toString('utf8'), message.toString('utf8'))

  //pack auth
  var recipient_verkeys = JSON.stringify([stewardVerkey])
  var auth_pack_message = await indy.cryptoPackMessage(wh, message, recipient_verkeys, trusteeVerkey)
  t.true(Buffer.isBuffer(auth_pack_message))

  var auth_unpack_message = await indy.cryptoUnpackMessage(wh, auth_pack_message)
  var auth_json = JSON.parse(auth_unpack_message)
  t.is(auth_json.recipient_verkey, stewardVerkey)
  t.is(auth_json.sender_verkey, trusteeVerkey)
  t.is(auth_json.message.toString('utf8'), message.toString('utf8'))

    //pack anon
  var anon_pack_message = await indy.cryptoPackMessage(wh, message, recipient_verkeys, null)
  t.true(Buffer.isBuffer(anon_pack_message))

  var anon_unpack_message = await indy.cryptoUnpackMessage(wh, auth_pack_message)
  var anon_json = JSON.parse(auth_unpack_message)
  t.is(anon_json.recipient_verkey, stewardVerkey)
  t.is(anon_json.sender_verkey, trusteeVerkey)
  t.is(anon_json.message.toString('utf8'), message.toString('utf8'))

  await indy.closeWallet(wh)
  await indy.deleteWallet(walletConfig, walletCredentials)
  pool.cleanup()
})
