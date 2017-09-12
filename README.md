# DNA : JavaScript-SDK

> Onchain DNA项目的JS-SDK。
  
## Demo:
index.html  
app.js



## 功能列表：
- 生成钱包
  - 新建钱包
  - 从私钥导入
  - 从WIF导入
- 发送交易
  - 选择钱包
  - 打开钱包
    - 通过密钥文件
    - 通过私钥
    - 通过WIF
    - 通过外部签名
  - 钱包信息
    - 账户信息
      - 选择账户
      - 地址
      - 脚本哈希
      - 公钥（压缩）
      - 账户余额
  - 发送交易
    - 交易类型
      - Transfer Asset
        - 发送到对方地址
        - 发送数量
        - 发送自我的地址
      - Issue Asset
        - 发行资产ID
        - 发行总量
      - Register Asset
        - 资产名称
        - 资产总量
      - State Update
        - Namespace
        - Key
        - Value
        - My ProgramHash
- 数据签名
  - 私钥
  - 交易待签名数据
  - 签名值
  - 签名
- 工具
  - 数据反转
  - 从WIF格式私钥生成私钥
  - 从私钥生成公钥
  - 从公钥生成公钥（压缩）
  - 从公钥（压缩）生成脚本
  - 从脚本生成脚本哈希
  - 从脚本哈希生成地址
- 切换中英文
- 切换连接节点



## API列表：

- #### Make register transaction - 注册资产交易
```angular2html
/**
 * Make register transaction and get transaction unsigned data.
 * 发起一个DNA注册资产交易和获取交易数据（十六进制）。
 * 不兼容小蚁股（NEO）
 *
 * @param $assetName
 * @param $assetAmount
 * @param $publicKeyEncoded
 *
 * @returns {string} : txUnsignedData
 */
Wallet.makeRegisterTransaction_DNA = function ($assetName, $assetAmount, $publicKeyEncoded) {
	return data;
};


/**
 * Make register transaction and get transaction unsigned data.
 * 发起一个NEO注册资产交易和获取交易数据（十六进制）。
 * 兼容小蚁股（NEO）
 *
 * @param $assetName
 * @param $assetAmount
 * @param $publicKeyEncoded
 * @param $programHash
 *
 * @returns {string} : txUnsignedData
 */
Wallet.makeRegisterTransaction_NEO = function ($assetName, $assetAmount, $publicKeyEncoded, $programHash) {
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
