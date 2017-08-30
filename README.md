# DNASDKJavaScript

> Onchain DNA项目的JS-SDK。



# DNA JAVASCRIPT SDK
## FUNCTIONS REFERENCE

- ### makeRegisterTransaction($assetName, $assetAmount, $publicKeyEncoded)
  description:
  Make register transaction and get transaction unsigned data.

  paramer:
  	string assetName
  	float  assetAmount
  	string publickeyEncoded
  return:
  	string txUnsignedData


- ### makeIssueTransaction($issueAssetID, $issueAmount, $publicKeyEncoded)
  description:
  Make issue transaction and get transaction unsigned data.

  paramer:
  	string issueAssetID
  	float  issueAmount
  	string publicKeyEncoded
  return:
  	string TxUnsignedData

- ### makeTransferTransaction($coin, $publicKeyEncoded, $toAddress, $Amount)
  description:
  Make transfer transaction and get transaction unsigned data.

  paramer:
  	struct coin
  	string toAddress
  	float  amount
  	string publicKeyEncoded
  return:
  	string TxUnsignedData

- ### makeStateUpdateTransaction( $namespace, $key, $value, $publicKeyEncoded )
  description:
  Make StateUpdate transaction and get transaction unsigned data.

  paramer:
  	string namespace
  	string key
  	string value
  	string publicKeyEncoded
  return:
  	string TxUnsignedData

- ### createAccount($privateKey, $password)
  description:
  Create account use random privatekey.

  paramer:
  	string privateKey
  	string password
  return:
  	struct Account

- ### createAccountsFromPrivateKey($privateKey)
  description:
  Create account from privatekey.

  paramer:
  	string privateKey
  return:
  	struct Account

- ### createAccountsFromWIFKey($WIFKey)
  description:
  Create account from WIFKey.

  paramer:
  	string WIFKey
  return:
  	struct Account

- ### signatureData($data, $privateKey)
  description:
  signature transaction unsigned Data

  paramer:
  	string data
    string privateKey
  return:
  	string signedData

- ### toAddress($ProgramHash)
  description:
  Programhash to address

  paramer:
  	string ProgramHash
  return:
  	string address

- ### toScriptHash($address)
  description:
  Address to scriptHash

  paramer:
  	string address
  return:
  	string scriptHash