var ecurve = require('ecurve');
var BigInteger = require('bigi');
var ecdsa = require('ecdsa');
var CoinKey = require('CoinKey');
var Buffer = require('Buffer');
var sr = require('secure-random');
var cryptos = require('crypto');
var secp256r1 = require('secp256k1');
var randomBytes = require('crypto').randomBytes;
var BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
var base58 = require('base-x')(BASE58);
//var sm2 = require('sm.js').sm2;
//var sm3 = require('sm.js').sm3;transferTransactionUnsigned

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function str2ab(str) {
    var bufView = new Uint8Array(str.length);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return bufView;
}

function hexstring2ab(str) {
    var result = [];
    while (str.length >= 2) {
        result.push(parseInt(str.substring(0, 2), 16));
        str = str.substring(2, str.length);
    }

    return result;
}

function ab2hexstring(arr) {
    var result = "";
    for (i = 0; i < arr.length; i++) {
        var str = arr[i].toString(16);
        str = str.length == 0 ? "00" :
            str.length == 1 ? "0" + str :
                str;
        result += str;
    }
    return result;
}

function reverseArray(arr) {
    var result = new Uint8Array(arr.length);
    for (i = 0; i < arr.length; i++) {
        result[i] = arr[arr.length - 1 - i];
    }

    return result;
}

function numStoreInMemory(num, length) {
    if (num.length % 2 == 1) {
        num = '0' + num;
    }

    for (i = num.length; i < length; i++) {
        num = '0' + num;
    }

    var data = reverseArray(new Buffer(num, "HEX"));

    return ab2hexstring(data);
}

function stringToBytes(str) {
    var utf8 = unescape(encodeURIComponent(str));

    var arr = [];
    for (var i = 0; i < utf8.length; i++) {
        arr.push(utf8.charCodeAt(i));
    }

    return arr;
}

/**
 * 补全数字串前的0
 *
 * @param num 数字串
 * @param length 需要多长
 * @return {string}
 */
function prefixInteger(num, length) {
    return (new Array(length).join('0') + num).slice(-length);
}

var Wallet = function Wallet(passwordHash, iv, masterKey, publicKeyHash, privateKeyEncrypted) {
    this.passwordHash = passwordHash;
    this.iv = iv;
    this.masterKey = masterKey;
    this.publicKeyHash = publicKeyHash;
    this.privateKeyEncrypted = privateKeyEncrypted;
};

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
    //console.log( "privateKey: ", $privateKey );
    //console.log( "password: ", $password );

    var publicKey = Wallet.getPublicKey($privateKey, false);
    //console.log( "publicKey: ", publicKey.toString('hex') );

    var publicKeyEncoded = Wallet.getPublicKey($privateKey, true);
    //console.log( "publicKeyEncoded: ", publicKeyEncoded.toString('hex') );

    var scriptCode = Wallet.createSignatureScript(publicKeyEncoded);
    //console.log( "scriptCode: ", scriptCode );

    var scriptHash = Wallet.getHash(scriptCode);
    //console.log( "scriptHash: ", scriptHash.toString() );

    var publicKeyHash = Wallet.getHash(publicKeyEncoded.toString('hex'));
    //console.log( "publicKeyHash: ", publicKeyHash.toString() );

    var passwordKey = CryptoJS.SHA256(CryptoJS.SHA256($password));
    var passwordHash = CryptoJS.SHA256(passwordKey);
    //console.log( "passwordHash: ", passwordHash.toString() );

    var iv = Wallet.generateRandomArray(16);
    //console.log( "iv: ", ab2hexstring(iv) );

    var masterKey = Wallet.generateRandomArray(32);
    //console.log( "masterKey: ", ab2hexstring(masterKey) );

    // Encrypt MasterKey
    var masterKeyPlain = CryptoJS.enc.Hex.parse(ab2hexstring(masterKey));
    var key = CryptoJS.enc.Hex.parse(passwordKey.toString());
    var ivData = CryptoJS.enc.Hex.parse(ab2hexstring(iv));
    var masterKeyEncrypt = CryptoJS.AES.encrypt(masterKeyPlain, key, {
        iv: ivData,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding
    });
    //console.log( "masterKeyEncrypt: ", masterKeyEncrypt.ciphertext.toString() );

    // PrivateKey Data
    var privateKeyData = publicKey.slice(1, 65).toString('hex') + $privateKey;
    //console.log( "privateKeyData: ", privateKeyData );

    // Encrypt PrivateKey Data
    var privateKeyDataPlain = CryptoJS.enc.Hex.parse(privateKeyData);
    var privateKeyDataEncrypted = CryptoJS.AES.encrypt(privateKeyDataPlain, masterKeyPlain, {
        iv: ivData,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding
    });
    //console.log( "privateKeyDataEncrypted: ", privateKeyDataEncrypted.ciphertext.toString() );

    var db = new SQL.Database();

    var sqlstr = "CREATE TABLE Account ( PublicKeyHash BINARY NOT NULL CONSTRAINT PK_Account PRIMARY KEY, PrivateKeyEncrypted VARBINARY NOT NULL );";
    sqlstr += "CREATE TABLE Address ( ScriptHash BINARY NOT NULL CONSTRAINT PK_Address PRIMARY KEY );";
    sqlstr += "CREATE TABLE Coin ( TxId BINARY  NOT NULL, [Index] INTEGER NOT NULL, AssetId BINARY NOT NULL, ScriptHash BINARY  NOT NULL, State INTEGER NOT NULL, Value INTEGER NOT NULL, CONSTRAINT PK_Coin PRIMARY KEY ( TxId, [Index] ), CONSTRAINT FK_Coin_Address_ScriptHash FOREIGN KEY ( ScriptHash ) REFERENCES Address (ScriptHash) ON DELETE CASCADE );";
    sqlstr += "CREATE TABLE Contract ( ScriptHash BINARY NOT NULL CONSTRAINT PK_Contract PRIMARY KEY, PublicKeyHash BINARY NOT NULL, RawData VARBINARY NOT NULL, CONSTRAINT FK_Contract_Account_PublicKeyHash FOREIGN KEY ( PublicKeyHash ) REFERENCES Account (PublicKeyHash) ON DELETE CASCADE, CONSTRAINT FK_Contract_Address_ScriptHash FOREIGN KEY ( ScriptHash ) REFERENCES Address (ScriptHash) ON DELETE CASCADE );";
    sqlstr += "CREATE TABLE [Key] ( Name VARCHAR NOT NULL CONSTRAINT PK_Key PRIMARY KEY, Value VARBINARY NOT NULL );";
    sqlstr += "CREATE TABLE [Transaction] ( Hash BINARY NOT NULL CONSTRAINT PK_Transaction PRIMARY KEY, Height INTEGER, RawData VARBINARY NOT NULL, Time TEXT NOT NULL, Type INTEGER NOT NULL );";
    db.run(sqlstr);

    // Account table
    var stmtAccount = db.prepare("INSERT INTO Account(PublicKeyHash,PrivateKeyEncrypted) VALUES (?,?)");
    stmtAccount.run([hexstring2ab(publicKeyHash.toString()), hexstring2ab(privateKeyDataEncrypted.ciphertext.toString())]);
    stmtAccount.free();

    // Address table
    var stmtAddress = db.prepare("INSERT INTO Address(ScriptHash) VALUES (?)");
    stmtAddress.run([hexstring2ab(scriptHash.toString())]);
    stmtAddress.free();

    // Contract table
    var stmtContract = db.prepare("INSERT INTO Contract(ScriptHash,PublicKeyHash,RawData) VALUES (?,?,?)");
    stmtContract.run([hexstring2ab(scriptHash.toString()), hexstring2ab(publicKeyHash.toString()), hexstring2ab(publicKeyHash.toString() + "010023" + scriptCode)]);
    stmtContract.free();

    // Key table
    var stmtKey = db.prepare("INSERT INTO Key(Name,Value) VALUES (?,?)");
    stmtKey.run(['PasswordHash', hexstring2ab(passwordHash.toString())]);
    stmtKey.free();

    stmtKey = db.prepare("INSERT INTO Key(Name,Value) VALUES (?,?)");
    stmtKey.run(['IV', iv]);
    stmtKey.free();

    stmtKey = db.prepare("INSERT INTO Key(Name,Value) VALUES (?,?)");
    stmtKey.run(['MasterKey', hexstring2ab(masterKeyEncrypt.ciphertext.toString())]);
    stmtKey.free();

    stmtKey = db.prepare("INSERT INTO Key(Name,Value) VALUES (?,?)");
    stmtKey.run(['Version', hexstring2ab("01000000060000000000000000000000")]);
    stmtKey.free();

    stmtKey = db.prepare("INSERT INTO Key(Name,Value) VALUES (?,?)");
    stmtKey.run(['Height', hexstring2ab("00000000")]);
    stmtKey.free();

    var binaryArray = db.export();

    return binaryArray;
};

Wallet.Sha256 = function ($data) {
    var DataHexString = CryptoJS.enc.Hex.parse($data);
    var DataSha256 = CryptoJS.SHA256(DataHexString);

    return DataSha256.toString();
};

Wallet.SM3 = function ($data) {
    var x = sm3();
    var DataHexString = hexstring2ab($data);
    return ab2hexstring(x.sum(DataHexString));
};

Wallet.MD5 = function ($data) {
    var DataHexString = CryptoJS.enc.Hex.parse($data);
    return CryptoJS.MD5(DataHexString).toString();
};

Wallet.GetTxHash = function ($data) {
    var DataHexString = CryptoJS.enc.Hex.parse($data);
    var DataSha256 = CryptoJS.SHA256(DataHexString);
    var DataSha256_2 = CryptoJS.SHA256(DataSha256);

    return DataSha256_2.toString();
};

Wallet.GetInputData = function ($coin, $amount) {
    // sort
    var coin_ordered = $coin['Utxo'];
    for (i = 0; i < coin_ordered.length - 1; i++) {
        for (j = 0; j < coin_ordered.length - 1 - i; j++) {
            if (parseFloat(coin_ordered[j].Value) < parseFloat(coin_ordered[j + 1].Value)) {
                var temp = coin_ordered[j];
                coin_ordered[j] = coin_ordered[j + 1];
                coin_ordered[j + 1] = temp;
            }
        }
    }

    //console.log( coin_ordered );

    // calc sum
    var sum = 0;
    for (i = 0; i < coin_ordered.length; i++) {
        sum = sum + parseFloat(coin_ordered[i].Value);
    }

    // if sum < amount then exit;
    var amount = parseFloat($amount);
    if (sum < amount) return -1;

    // find input coins
    var k = 0;
    while (parseFloat(coin_ordered[k].Value) <= amount) {
        amount = amount - parseFloat(coin_ordered[k].Value);
        if (amount == 0) break;
        k = k + 1;
    }

    /////////////////////////////////////////////////////////////////////////
    // coin[0]- coin[k]
    var data = new Uint8Array(1 + 34 * (k + 1));

    // input num
    var inputNum = numStoreInMemory((k + 1).toString(16), 2);
    data.set(hexstring2ab(inputNum));

    // input coins
    for (var x = 0; x < k + 1; x++) {
        // txid
        var pos = 1 + (x * 34);
        data.set(reverseArray(hexstring2ab(coin_ordered[x]['Txid'])), pos);
        //data.set(hexstring2ab(coin_ordered[x]['txid']), pos);

        // index
        pos = 1 + (x * 34) + 32;
        inputIndex = numStoreInMemory(coin_ordered[x]['Index'].toString(16), 4);
        //inputIndex = numStoreInMemory(coin_ordered[x]['Index'].toString(16), 2);
        data.set(hexstring2ab(inputIndex), pos);
    }

    /////////////////////////////////////////////////////////////////////////

    // calc coin_amount
    var coin_amount = 0;
    for (i = 0; i < k + 1; i++) {
        coin_amount = coin_amount + parseFloat(coin_ordered[i].Value);
    }

    /////////////////////////////////////////////////////////////////////////

    return {
        amount: coin_amount,
        data: data
    }

};

/**
 * Make state update transaction and get transaction unsigned data.
 * 发起一个状态更新交易。
 *
 * @param $namespace
 * @param $key
 * @param $value
 * @param $publicKeyEncoded
 *
 * @returns {string}
 */
Wallet.makeStateUpdateTransaction = function ($namespace, $key, $value, $publicKeyEncoded) {
    var ecparams = ecurve.getCurveByName('secp256r1');
    var curvePt = ecurve.Point.decodeFrom(ecparams, new Buffer($publicKeyEncoded, "hex"));
    var curvePtX = curvePt.affineX.toBuffer(32);
    var curvePtY = curvePt.affineY.toBuffer(32);

    ////////////////////////////////////////////////////////////////////////
    // data
    var data = "90";

    // version
    data = data + "00";

    ///////////////////////
    // stateUpdate payload

    // namespace
    namespacelen = numStoreInMemory($namespace.length.toString(16), 0);
    data = data + namespacelen + ab2hexstring(str2ab($namespace));

    // key
    keylen = numStoreInMemory($key.length.toString(16), 0);
    data = data + keylen + ab2hexstring(str2ab($key));

    // value
    valuelen = numStoreInMemory($value.length.toString(16), 0);
    data = data + valuelen + ab2hexstring(str2ab($value));

    // publickey
    var publicKeyXStr = curvePtX.toString('hex');
    var publicKeyYStr = curvePtY.toString('hex');
    data = data + "20" + publicKeyXStr + "20" + publicKeyYStr;

    // attribute
    data = data + "00";

    // Inputs
    data = data + "00";

    // Outputs
    data = data + "00";

    return data;
};

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
    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);
    //console.log( signatureScript.toString('hex') );

    var myProgramHash = Wallet.getHash(signatureScript);
    //console.log( myProgramHash.toString() );

    ////////////////////////////////////////////////////////////////////////
    // data
    var data = "01";

    // version
    data = data + "00";

    // attribute
    data = data + "00";

    // Inputs
    data = data + "00";

    // Outputs len
    data = data + "01";

    // Outputs[0] AssetID
    data = data + ab2hexstring(reverseArray(hexstring2ab($issueAssetID)));

    // Outputs[0] Amount
    num1 = $issueAmount * 100000000;
    num1str = numStoreInMemory(num1.toString(16), 16);
    data = data + num1str;

    // Outputs[0] ProgramHash
    data = data + myProgramHash.toString();

    //console.log(data);

    return data;
};

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
    var ecparams = ecurve.getCurveByName('secp256r1');
    var curvePt = ecurve.Point.decodeFrom(ecparams, new Buffer($publicKeyEncoded, "hex"));
    var curvePtX = curvePt.affineX.toBuffer(32);
    var curvePtY = curvePt.affineY.toBuffer(32);
    var publicKey = Buffer.concat([new Buffer([0x04]), curvePtX, curvePtY]);

    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);

    var myProgramHash = Wallet.getHash(signatureScript);

    // data
    var data = "40";

    // version
    data = data + "00";

    // asset name
    var assetName = ab2hexstring(stringToBytes($assetName));
    var assetNameLen = (assetName.length / 2).toString();
    if (assetNameLen.length == 1) assetNameLen = "0" + assetNameLen;
    data = data + assetNameLen + assetName;

    // asset desc
    var assetDesc = assetName;
    var assetDescLen = assetNameLen;
    data = data + assetDescLen + assetDesc;

    // asset precision
    data = data + "00";

    // asset type
    data = data + "01";

    // asset recordtype
    data = data + "00";

    // asset amount
    num1 = $assetAmount * 100000000;
    num1str = numStoreInMemory(num1.toString(16), 16);
    data = data + num1str;

    // publickey
    var publicKeyXStr = curvePtX.toString('hex');
    var publicKeyYStr = curvePtY.toString('hex');

    data = data + "20" + publicKeyXStr + "20" + publicKeyYStr;
    data = data + myProgramHash.toString();
    data = data + "000000";

    return data;
};

/**
 * Make register transaction and get transaction unsigned data.
 * 发起一个NEO注册资产交易和获取交易数据（十六进制）。
 * 兼容小蚁股（NEO）
 *
 * 数据格式：
 * 字节            内容
 * 1              type ： 40
 * 1              version  ： 00
 * 1              资产类型  ： 00
 * 1              名字长度
 * 名字实际长度     名字
 * 8              资产数量（小端序）：乘以1亿
 * 1              资产精度 ： 08
 * 33             压缩的公钥
 * 20             资产控制人
 * 1              交易属性个数：Web端存0
 * 1              交易属性中的用法：个数为0时，则无
 * 8              交易属性中的数据长度：个数为0时，则无
 * 数据实际长度     交易属性中的数据：个数为0时，则无
 * 1              交易输入个数：Web端存0
 * 32             引用交易hash：个数为0时，则无
 * 2              引用输出索引：个数为0时，则无
 * 1              交易输出个数：Web端存0
 * 32             资产ID：个数为0时，则无
 * 8              资产数量：个数为0时，则无
 * 20             资产ProgramHash：个数为0时，则无
 * 1              Program长度：0x01
 * 1              参数长度 parameter
 * 参数实际长度 	  参数：签名
 * 1			  代码长度 code
 * 代码实际长度     代码：公钥
 *
 * @param $assetName
 * @param $assetAmount
 * @param $publicKeyEncoded
 * @param $programHash
 *
 * @returns {string} : txUnsignedData
 */
Wallet.makeRegisterTransaction_NEO = function ($assetName, $assetAmount, $publicKeyEncoded, $programHash) {
    var ecparams = ecurve.getCurveByName('secp256r1');
    var curvePt = ecurve.Point.decodeFrom(ecparams, new Buffer($publicKeyEncoded, "hex"));
    var curvePtX = curvePt.affineX.toBuffer(32);
    var curvePtY = curvePt.affineY.toBuffer(32);
    var publicKey = Buffer.concat([new Buffer([0x04]), curvePtX, curvePtY]);

    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);
    var myProgramHash = Wallet.getHash(signatureScript);

    /**
     * 数据拼接：
     */
    var type = "40";
    var version = "00";
    var assetType = "00";
    var assetNameLen = prefixInteger((Number($assetName.length).toString( 16 )), 2);
    var assetName = ab2hexstring(stringToBytes($assetName));
    var assetAmount = prefixInteger((Number($assetAmount) * 100000000).toString( 16 ), 16);
    var assetAccuracy = "08"; //资产精度
    var publicKey = $publicKeyEncoded;
    var programHash = $programHash;

    var transactionAttrNum = "00";
    //TODO:后续还需要加一些参数
    var transactionInputNum = "00";
    //TODO:后续还需要加一些参数
    var transactionOutputNum = "00";
    //TODO:后续还需要加一些参数

    // var progarmLength = "01";

    data = type + version +
        assetType + assetNameLen + assetName + assetAmount + assetAccuracy +
        publicKey + programHash +
        transactionAttrNum + transactionInputNum + transactionOutputNum;

    return data;
};

/**
 *
 * @param $txData
 * @param $sign
 * @param $publicKeyEncoded
 * @return {string}
 * @constructor
 */
Wallet.AddContract = function ($txData, $sign, $publicKeyEncoded) {
    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);

    // sign num
    var data = $txData + "01";
    // sign struct len
    data = data + "41";
    // sign data len
    data = data + "40";
    // sign data
    data = data + $sign;
    // Contract data len
    data = data + "23";
    // script data
    data = data + signatureScript;

    return data;
};

/**
 * Address to program hash.
 * 地址转脚本哈希。
 *
 * @param $toAddress
 * @return {number}
 *
 * @constructor
 */
Wallet.AddressToProgramHash = function ($toAddress) {
    var ProgramHash = base58.decode($toAddress);
    var ProgramHexString = CryptoJS.enc.Hex.parse(ab2hexstring(ProgramHash.slice(0, 21)));
    var ProgramSha256 = CryptoJS.SHA256(ProgramHexString);
    var ProgramSha256_2 = CryptoJS.SHA256(ProgramSha256);
    var ProgramSha256Buffer = hexstring2ab(ProgramSha256_2.toString());

    if (ab2hexstring(ProgramSha256Buffer.slice(0, 4)) != ab2hexstring(ProgramHash.slice(21, 25))) {
        //address verify failed.
        return -1;
    }

    return ab2hexstring(ProgramHash);
};

/**
 *
 * @param $toAddress
 * @return {boolean}
 * @constructor
 */
Wallet.VerifyAddress = function ($toAddress) {
    var ProgramHash = base58.decode($toAddress);
    var ProgramHexString = CryptoJS.enc.Hex.parse(ab2hexstring(ProgramHash.slice(0, 21)));
    var ProgramSha256 = CryptoJS.SHA256(ProgramHexString);
    var ProgramSha256_2 = CryptoJS.SHA256(ProgramSha256);
    var ProgramSha256Buffer = hexstring2ab(ProgramSha256_2.toString());

    if (ab2hexstring(ProgramSha256Buffer.slice(0, 4)) != ab2hexstring(ProgramHash.slice(21, 25))) {
        //address verify failed.
        return false;
    }

    return true;
};

/**
 *
 * @param $publicKeyEncoded
 * @return {boolean}
 * @constructor
 */
Wallet.VerifyPublicKeyEncoded = function ($publicKeyEncoded) {
    var publicKeyArray = hexstring2ab($publicKeyEncoded);
    if (publicKeyArray[0] != 0x02 && publicKeyArray[0] != 0x03) {
        return false;
    }

    var ecparams = ecurve.getCurveByName('secp256r1');
    var curvePt = ecurve.Point.decodeFrom(ecparams, new Buffer($publicKeyEncoded, "hex"));
    var curvePtX = curvePt.affineX.toBuffer(32);
    var curvePtY = curvePt.affineY.toBuffer(32);

    // console.log( "publicKeyArray", publicKeyArray );
    // console.log( "curvePtX", curvePtX );
    // console.log( "curvePtY", curvePtY );

    if (publicKeyArray[0] == 0x02 && curvePtY[31] % 2 == 0) {
        return true;
    }

    if (publicKeyArray[0] == 0x03 && curvePtY[31] % 2 == 1) {
        return true;
    }

    return false;
};

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
    var ProgramHash = base58.decode($toAddress);
    var ProgramHexString = CryptoJS.enc.Hex.parse(ab2hexstring(ProgramHash.slice(0, 21)));
    var ProgramSha256 = CryptoJS.SHA256(ProgramHexString);
    var ProgramSha256_2 = CryptoJS.SHA256(ProgramSha256);
    var ProgramSha256Buffer = hexstring2ab(ProgramSha256_2.toString());

    if (ab2hexstring(ProgramSha256Buffer.slice(0, 4)) != ab2hexstring(ProgramHash.slice(21, 25))) {
        //address verify failed.
        return -1;
    }

    ProgramHash = ProgramHash.slice(1, 21);

    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);
    var myProgramHash = Wallet.getHash(signatureScript);

    // INPUT CONSTRUCT
    var inputData = Wallet.GetInputData($coin, $Amount);
    if (inputData == -1) return null;
    //console.log( inputData );

    var inputLen = inputData.data.length;
    var inputAmount = inputData.amount;

    // Set SignableData Len
    var signableDataLen = 124 + inputLen;
    if (inputAmount == $Amount) {
        signableDataLen = 64 + inputLen;
    }

    // CONSTRUCT
    var data = new Uint8Array(signableDataLen);

    // type
    data.set(hexstring2ab("80"), 0);

    // version
    data.set(hexstring2ab("00"), 1);

    // Attributes
    data.set(hexstring2ab("00"), 2);

    // INPUT
    data.set(inputData.data, 3);

    // OUTPUT
    if (inputAmount == $Amount) {
        // only one output

        // output num
        data.set(hexstring2ab("01"), inputLen + 3);

        ////////////////////////////////////////////////////////////////////
        // OUTPUT - 0

        // output asset
        data.set(reverseArray(hexstring2ab($coin['AssetId'])), inputLen + 4);
        //data.set(hexstring2ab($coin['AssetId']), inputLen + 4);

        // output value
        num1 = $Amount * 100000000;
        num1str = numStoreInMemory(num1.toString(16), 16);
        data.set(hexstring2ab(num1str), inputLen + 36);

        // output ProgramHash
        data.set(ProgramHash, inputLen + 44);

        ////////////////////////////////////////////////////////////////////

    } else {
        // output num
        data.set(hexstring2ab("02"), inputLen + 3);

        ////////////////////////////////////////////////////////////////////
        // OUTPUT - 0

        // output asset
        data.set(reverseArray(hexstring2ab($coin['AssetId'])), inputLen + 4);
        //data.set(hexstring2ab($coin['AssetId']), inputLen + 4);

        // output value
        num1 = $Amount * 100000000;
        //console.log("num1:", num1)
        num1str = numStoreInMemory(num1.toString(16), 16);
        data.set(hexstring2ab(num1str), inputLen + 36);

        // output ProgramHash
        data.set(ProgramHash, inputLen + 44);

        ////////////////////////////////////////////////////////////////////
        // OUTPUT - 1

        // output asset
        data.set(reverseArray(hexstring2ab($coin['AssetId'])), inputLen + 64);
        //data.set(hexstring2ab($coin['AssetId']), inputLen + 64);

        // output value
        num2 = inputAmount * 100000000 - num1;
        //console.log("num2:", num2)
        num2str = numStoreInMemory(num2.toString(16), 16);
        data.set(hexstring2ab(num2str), inputLen + 96);

        // output ProgramHash
        data.set(hexstring2ab(myProgramHash.toString()), inputLen + 104);

        ////////////////////////////////////////////////////////////////////

        //console.log( "Signature Data:", ab2hexstring(data) );
    }

    return ab2hexstring(data);
};

/**
 * @return {string}
 */
Wallet.ClaimTransaction = function ($claims, $publicKeyEncoded, $toAddress, $Amount) {
    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);
    //console.log( signatureScript.toString('hex') );

    var myProgramHash = Wallet.getHash(signatureScript);
    //console.log( myProgramHash.toString() );

    ////////////////////////////////////////////////////////////////////////
    // data
    var data = "02";

    // version
    data = data + "00";

    // claim
    // TODO: !!! var int
    len = $claims['claims'].length;
    lenstr = numStoreInMemory(len.toString(16), 2);
    data = data + lenstr;

    //console.log("len: ", len);
    for (var k = 0; k < len; k++) {
        txid = $claims['claims'][k]['txid'];
        data = data + ab2hexstring(reverseArray(hexstring2ab(txid)));

        vout = $claims['claims'][k]['vout'].toString(16);
        data = data + numStoreInMemory(vout, 4);
    }

    // attribute
    data = data + "00";

    // Inputs
    data = data + "00";

    // Outputs len
    data = data + "01";

    // Outputs[0] AssetID
    data = data + ab2hexstring(reverseArray(hexstring2ab($claims['assetid'])));

    // Outputs[0] Amount
    num1 = parseInt($Amount);
    num1str = numStoreInMemory(num1.toString(16), 16);
    data = data + num1str;

    // Outputs[0] ProgramHash
    data = data + myProgramHash.toString();

    //console.log(data);

    return data;
};

/**
 * Program hash to address.
 * 脚本哈希转地址。
 *
 * @param $ProgramHash
 *
 * @return {*}
 */
Wallet.toAddress = function ($ProgramHash) {
    var data = new Uint8Array(1 + $ProgramHash.length);
    data.set([23]);
    data.set($ProgramHash, 1);

    var ProgramHexString = CryptoJS.enc.Hex.parse(ab2hexstring(data));
    var ProgramSha256 = CryptoJS.SHA256(ProgramHexString);
    var ProgramSha256_2 = CryptoJS.SHA256(ProgramSha256);
    var ProgramSha256Buffer = hexstring2ab(ProgramSha256_2.toString());

    var datas = new Uint8Array(1 + $ProgramHash.length + 4);
    datas.set(data);
    datas.set(ProgramSha256Buffer.slice(0, 4), 21);

    return base58.encode(datas);
};

Wallet.generateRandomArray = function ($arrayLen) {
    var randomArray = new Uint8Array($arrayLen);
    for (i = 0; i < $arrayLen; i++) {
        randomArray[i] = Math.floor(Math.random() * 256);
    }

    return randomArray;
};

Wallet.generatePrivateKey = function () {
    var privateKey = new Uint8Array(32);
    for (i = 0; i < 32; i++) {
        privateKey[i] = Math.floor(Math.random() * 256);
    }

    return privateKey;
};

/**
 * Create account from WIF key.
 * 从WIF Key创建账户。
 *
 * @param $wif
 *
 * @return {*}
 */
Wallet.getPrivateKeyFromWIF = function ($wif) {
    var data = base58.decode($wif);

    if (data.length != 38 || data[0] != 0x80 || data[33] != 0x01) {
        return -1;
    }

    var dataHexString = CryptoJS.enc.Hex.parse(ab2hexstring(data.slice(0, data.length - 4)));
    var dataSha256 = CryptoJS.SHA256(dataHexString);
    var dataSha256_2 = CryptoJS.SHA256(dataSha256);
    var dataSha256Buffer = hexstring2ab(dataSha256_2.toString());

    if (ab2hexstring(dataSha256Buffer.slice(0, 4)) != ab2hexstring(data.slice(data.length - 4, data.length))) {
        //wif verify failed.
        return -2;
    }

    return data.slice(1, 33).toString("hex");
};

Wallet.getPublicKey = function ($privateKey, $encode) {
    var ecparams = ecurve.getCurveByName('secp256r1');
    var curvePt = ecparams.G.multiply(BigInteger.fromBuffer(hexstring2ab($privateKey)));
    return curvePt.getEncoded($encode);
};

Wallet.getPublicKeyEncoded = function ($publicKey) {
    var publicKeyArray = hexstring2ab($publicKey);
    if (publicKeyArray[64] % 2 == 1) {
        return "03" + ab2hexstring(publicKeyArray.slice(1, 33));
    } else {
        return "02" + ab2hexstring(publicKeyArray.slice(1, 33));
    }
};

Wallet.createSignatureScript = function ($publicKeyEncoded) {
    return "21" + $publicKeyEncoded.toString('hex') + "ac";
};

Wallet.getHash = function ($SignatureScript) {
    var ProgramHexString = CryptoJS.enc.Hex.parse($SignatureScript);
    var ProgramSha256 = CryptoJS.SHA256(ProgramHexString);
    return CryptoJS.RIPEMD160(ProgramSha256);
};

Wallet.getReverse = function ($data) {
    ab = hexstring2ab($data);
    len = ab.length;
    for (i = 0; i < len / 2; i++) {
        temp = ab[i];
        ab[i] = ab[len - i - 1];
        ab[len - i - 1] = temp;
    }
    return ab2hexstring(ab);
};

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
    var msg = CryptoJS.enc.Hex.parse($data);
    var msgHash = CryptoJS.SHA256(msg);
    var pubKey = secp256r1.publicKeyCreate(new Buffer($privateKey, "HEX"));
    var signature = secp256r1.sign(new Buffer(msgHash.toString(), "HEX"), new Buffer($privateKey, "HEX"));

    return signature.signature.toString('hex');
};

/**
 * @return {number}
 */
Wallet.GetAccountsFromPublicKeyEncoded = function ($publicKeyEncoded) {
    if (!Wallet.VerifyPublicKeyEncoded($publicKeyEncoded)) {
        // verify failed.
        return -1
    }

    var accounts = [];
    var publicKeyHash = Wallet.getHash($publicKeyEncoded);
    var script = Wallet.createSignatureScript($publicKeyEncoded);
    var programHash = Wallet.getHash(script);
    var address = Wallet.toAddress(hexstring2ab(programHash.toString()));

    accounts[0] = {
        privatekey: '',
        publickeyEncoded: $publicKeyEncoded,
        publickeyHash: publicKeyHash.toString(),
        programHash: programHash.toString(),
        address: address
    };

    return accounts;
};

/**
 * @return {number}
 */
Wallet.GetAccountsFromPrivateKey = function ($privateKey) {
    if ($privateKey.length != 64) {
        return -1;
    }

    var accounts = [];
    var publicKeyEncoded = Wallet.getPublicKey($privateKey, true);
    var publicKeyHash = Wallet.getHash(publicKeyEncoded.toString('hex'));
    var script = Wallet.createSignatureScript(publicKeyEncoded);
    var programHash = Wallet.getHash(script);
    var address = Wallet.toAddress(hexstring2ab(programHash.toString()));

    accounts[0] = {
        privatekey: $privateKey,
        publickeyEncoded: publicKeyEncoded.toString('hex'),
        publickeyHash: publicKeyHash.toString(),
        programHash: programHash.toString(),
        address: address
    };

    return accounts;
};

/**
 *
 * @param $WIFKey
 * @return {*}
 * @constructor
 */
Wallet.GetAccountsFromWIFKey = function ($WIFKey) {
    var privateKey = Wallet.getPrivateKeyFromWIF($WIFKey);
    if (privateKey == -1 || privateKey == -2) {
        return privateKey;
    }

    return Wallet.GetAccountsFromPrivateKey(privateKey);
};

/**
 *
 * @param wallet
 * @param password
 * @return {*}
 */
Wallet.decryptWallet = function (wallet, password) {
    var accounts = [];
    var passwordhash1 = CryptoJS.SHA256(password);
    var passwordhash2 = CryptoJS.SHA256(passwordhash1);
    var passwordhash3 = CryptoJS.SHA256(passwordhash2);
    if (passwordhash3.toString() != ab2hexstring(wallet.passwordHash)) {
        //PASSWORD WRONG
        return -1;
    }

    // Decrypt MasterKey
    var data = CryptoJS.enc.Hex.parse(ab2hexstring(wallet.masterKey));
    var dataBase64 = CryptoJS.enc.Base64.stringify(data);
    var key = CryptoJS.enc.Hex.parse(passwordhash2.toString());
    var iv = CryptoJS.enc.Hex.parse(ab2hexstring(wallet.iv));

    var plainMasterKey = CryptoJS.AES.decrypt(dataBase64, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding
    });

    //console.log( "plainMasterKey:", plainMasterKey.toString());

    for (k = 0; k < wallet.privateKeyEncrypted.length; k++) {
        // Decrypt PrivateKey
        var privateKeyEncrypted = CryptoJS.enc.Hex.parse(ab2hexstring(wallet.privateKeyEncrypted[k]));
        var privateKeyBase64 = CryptoJS.enc.Base64.stringify(privateKeyEncrypted);
        var plainprivateKey = CryptoJS.AES.decrypt(privateKeyBase64, plainMasterKey, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.NoPadding
        });

        var privateKeyHexString = plainprivateKey.toString().slice(128, 192);

        // Verify PublicKeyHash
        var ecparams = ecurve.getCurveByName('secp256r1');
        var curvePt = ecparams.G.multiply(BigInteger.fromBuffer(hexstring2ab(privateKeyHexString)));

        // Get PublicKey
        //var x = curvePt.affineX.toBuffer(32);
        //var y = curvePt.affineY.toBuffer(32);
        //var publicKey = new Uint8Array(1+x.length+y.length);
        //publicKey.set([0x04]);
        //publicKey.set(x,1);
        //publicKey.set(y,1+x.length);
        //console.log(publicKey.toString('hex'));

        // Get PublicKeyEncoded
        var publicKeyEncoded = curvePt.getEncoded(true);
        //console.log( "publicKeyEncoded:", publicKeyEncoded.toString('hex') );

        // Get PublicKeyHash
        var publicKeyEncodedHexString = CryptoJS.enc.Hex.parse(publicKeyEncoded.toString('hex'));
        var publicKeyEncodedSha256 = CryptoJS.SHA256(publicKeyEncodedHexString);
        var publicKeyHash = CryptoJS.RIPEMD160(publicKeyEncodedSha256);

        // Get ProgramHash
        var ProgramHexString = CryptoJS.enc.Hex.parse("21" + publicKeyEncoded.toString('hex') + "ac");
        var ProgramSha256 = CryptoJS.SHA256(ProgramHexString);
        var ProgramHash = CryptoJS.RIPEMD160(ProgramSha256);

        // Get Address
        var address = Wallet.toAddress(hexstring2ab(ProgramHash.toString()));

        if (publicKeyHash.toString() != ab2hexstring(wallet.publicKeyHash[k])) {
            return -2;
        }

        accounts[k] = {
            privatekey: privateKeyHexString,
            publickeyEncoded: publicKeyEncoded.toString('hex'),
            publickeyHash: publicKeyHash.toString(),
            programHash: ProgramHash.toString(),
            address: address
        };
    }

    return accounts
};
