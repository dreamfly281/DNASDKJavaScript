# DNA : JavaScript-SDK

> Onchain DNA项目的JS-SDK。


## 功能列表：

- #### Make register transaction - 注册资产交易
```angular2html
/**
 * Make register transaction and get transaction unsigned data.
 * 发起一个注册资产交易和获取交易数据（十六进制）。
 * 
 * @param $assetName
 * @param $assetAmount
 * @param $publicKeyEncoded
 * 
 * @returns {string} : txUnsignedData
 */
Wallet.makeRegisterTransaction = function ($assetName, $assetAmount, $publicKeyEncoded) {
	return data;
};
```

- #### Make issue transaction - 发行资产交易
```angular2html
/**
 * Make issue transaction and get transaction unsigned data.
 * 发起一个发行资产交易和获取交易数据（十六进制）。
 * 
 * @param $issueAssetID
 * @param $issueAmount
 * @param $publicKeyEncoded
 * 
 * @returns {string} : TxUnsignedData
 */
Wallet.makeIssueTransaction = function ($issueAssetID, $issueAmount, $publicKeyEncoded) {
    return data;
};
```

- #### Make transfer transaction - 转账交易
```angular2html
/**
 * Make transfer transaction and get transaction unsigned data.
 * 发起一个转账交易和获取交易数据（十六进制）。
 * 
 * @param $coin
 * @param $publicKeyEncoded
 * @param $toAddress
 * @param $Amount
 * 
 * @returns {*} : TxUnsignedData
 */
Wallet.makeTransferTransaction = function ($coin, $publicKeyEncoded, $toAddress, $Amount) {
	return ab2hexstring(data);
};
```

- #### Make state update - 状态更新交易(DNA项目不会用到)
```angular2html
/**
 * Make state update transaction and get transaction unsigned data.
 * 发起一个状态更新交易，DNA项目不会用到。
 * @param $namespace
 * @param $key
 * @param $value
 * @param $publicKeyEncoded
 * 
 * @returns {string}
 */
Wallet.makeStateUpdateTransaction = function ( $namespace, $key, $value, $publicKeyEncoded ) {
    return data;
};
```

- #### Create account - 新建账户
```angular2html
/**
 * Create account use random private key.
 * 新建一个账户。
 * 
 * @param $privateKey
 * @param $password
 * 
 * @return $binaryArray : struct Account
 */
Wallet.createAccount = function ($privateKey, $password) {
	...
	var binaryArray = db.export();

	return binaryArray;
};
```

- #### Create account - 从私钥创建账户
```angular2html
// 同上，自定义私钥。
```

- #### Create account - 从WIF Key创建账户
```angular2html
/**
 * Create account from WIF key.
 * 从WIF Key创建账户。
 * 
 * @param $wif
 * 
 * @return {*}
 */
Wallet.getPrivateKeyFromWIF = function ($wif) {
    return data.slice(1, 33).toString("hex");
};
```

- #### Signature transaction - 生成签名
```angular2html
/**
 * Signature transaction unsigned Data.
 * 生成签名。
 * 
 * @param $data
 * @param $privateKey
 * 
 * @return {string}
 */
Wallet.signatureData = function ($data, $privateKey) {
	return signature.signature.toString('hex');
};
```

- #### Program hash to address - 脚本哈希转地址
```angular2html
/**
 * Program hash to address.
 * 脚本哈希转地址。
 * 
 * @param $ProgramHash
 * 
 * @return {*}
 */
Wallet.toAddress = function ($ProgramHash) {
    return base58.encode(datas);
};
```

- #### Address to program hash - 地址转脚本哈希
```angular2html
/**
 * Address to program hash.
 * 地址转脚本哈希。
 * 
 * @param $toAddress
 * @return {number}
 * 
 * @constructor
 */
Wallet.AddressToProgramHash = function ( $toAddress ) {
    return ab2hexstring(ProgramHash);
};
```
  