# DNA : JavaScript-SDK

> Onchain DNA项目的JS-SDK。


## 功能列表：

- ### makeRegisterTransaction($assetName, $assetAmount, $publicKeyEncoded)
  Description:
  Make register transaction and get transaction unsigned data.

  paramer:
  	string assetName
  	float  assetAmount
  	string publickeyEncoded
  return:
  	string txUnsignedData


- ### makeIssueTransaction($issueAssetID, $issueAmount, $publicKeyEncoded)
  Description:
  Make issue transaction and get transaction unsigned data.

  paramer:
  	string issueAssetID
  	float  issueAmount
  	string publicKeyEncoded
  return:
  	string TxUnsignedData

- ### makeTransferTransaction($coin, $publicKeyEncoded, $toAddress, $Amount)
  Description:
  Make transfer transaction and get transaction unsigned data.

  paramer:
  	struct coin
  	string toAddress
  	float  amount
  	string publicKeyEncoded
  return:
  	string TxUnsignedData

- ### makeStateUpdateTransaction( $namespace, $key, $value, $publicKeyEncoded )
  Description:
  Make StateUpdate transaction and get transaction unsigned data.

  paramer:
  	string namespace
  	string key
  	string value
  	string publicKeyEncoded
  return:
  	string TxUnsignedData

- ### createAccount($privateKey, $password)
  Description:
  Create account use random privatekey.

  paramer:
  	string privateKey
  	string password
  return:
  	struct Account

- ### createAccountsFromPrivateKey($privateKey)
  Description:
  Create account from privatekey.

  paramer:
  	string privateKey
  return:
  	struct Account

- ### createAccountsFromWIFKey($WIFKey)
  Description:
  Create account from WIFKey.

  paramer:
  	string WIFKey
  return:
  	struct Account

- ### signatureData($data, $privateKey)
  Description:
  signature transaction unsigned Data

  paramer:
  	string data
    string privateKey
  return:
  	string signedData

- ### toAddress($ProgramHash)
  Description:
  Programhash to address

  paramer:
  	string ProgramHash
  return:
  	string address

- ### toScriptHash($address)
  Description:
  Address to scriptHash

  paramer:
  	string address
  return:
  	string scriptHash