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
//var Decimal = require('decimal.js'); // 仅用于electron打包上



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



/**************************************************************
 * Accurate addition, subtraction, multiplication and division.
 * 精确的加/减/乘/除，比较，显示和十/十六进制转换。
 *
 * @constructor
 */
var WalletMath = function () {};
WalletMath.add = function (arg1, arg2) {
    return Decimal.add(arg1, arg2);
};
WalletMath.sub = function (arg1, arg2) {
    return Decimal.sub(arg1, arg2);
};
WalletMath.mul = function (arg1, arg2) {
    return Decimal.mul(arg1, arg2);
};
WalletMath.div = function (arg1, arg2) {
    return Decimal.div(arg1, arg2);
};
WalletMath.eq = function (arg1, arg2) {
    return new Decimal(arg1).eq(arg2);
};
WalletMath.lt = function (arg1, arg2) {
    // if (arg1 < arg2) return true;
    return new Decimal(arg1).lessThan(arg2);
};
WalletMath.lessThanOrEqTo = function (arg1, arg2) {
    // if (arg1 <= arg2) return true;
    return new Decimal(arg1).lessThanOrEqualTo(arg2);
};
WalletMath.fixView = function (arg) {
    return arg.toFixed(new Decimal(arg).dp());
};
WalletMath.toHex = function (arg) {
    var retData = new Decimal(arg).toHexadecimal();
    return retData.toString().substring(2); // Del 0x.
};
WalletMath.hexToNumToStr = function (arg) {
    return new Decimal("0x" + arg).toString();
};



/**************************************************************
 * Wallet Class.
 * Wallet api.
 * 钱包API。
 *
 * @param passwordHash
 * @param iv
 * @param masterKey
 * @param publicKeyHash
 * @param privateKeyEncrypted
 * @constructor
 */
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
    var publicKey = Wallet.getPublicKey($privateKey, false);
    var publicKeyEncoded = Wallet.getPublicKey($privateKey, true);
    var scriptCode = Wallet.createSignatureScript(publicKeyEncoded);
    var scriptHash = Wallet.getHash(scriptCode);
    var publicKeyHash = Wallet.getHash(publicKeyEncoded.toString('hex'));
    var passwordKey = CryptoJS.SHA256(CryptoJS.SHA256($password));
    var passwordHash = CryptoJS.SHA256(passwordKey);
    var iv = Wallet.generateRandomArray(16);
    var masterKey = Wallet.generateRandomArray(32);

    // Encrypt MasterKey
    var masterKeyPlain = CryptoJS.enc.Hex.parse(ab2hexstring(masterKey));
    var key = CryptoJS.enc.Hex.parse(passwordKey.toString());
    var ivData = CryptoJS.enc.Hex.parse(ab2hexstring(iv));
    var masterKeyEncrypt = CryptoJS.AES.encrypt(masterKeyPlain, key, {
        iv: ivData,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding
    });

    // PrivateKey Data
    var privateKeyData = publicKey.slice(1, 65).toString('hex') + $privateKey;

    // Encrypt PrivateKey Data
    var privateKeyDataPlain = CryptoJS.enc.Hex.parse(privateKeyData);
    var privateKeyDataEncrypted = CryptoJS.AES.encrypt(privateKeyDataPlain, masterKeyPlain, {
        iv: ivData,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding
    });

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

/**
 *
 * @param $data
 * @return {string}
 * @constructor
 */
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

/**
 *
 * @param $data
 * @return {string}
 * @constructor
 */
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
            if (WalletMath.lt(coin_ordered[j].Value, coin_ordered[j + 1].Value)) {
                var temp = coin_ordered[j];
                coin_ordered[j] = coin_ordered[j + 1];
                coin_ordered[j + 1] = temp;
            }
        }
    }

    // calc sum
    var sum = 0;
    for (i = 0; i < coin_ordered.length; i++) {
        sum = WalletMath.add(sum, coin_ordered[i].Value);
    }

    // if sum < amount then exit;
    var amount = $amount;
    if (WalletMath.lt(sum, amount)) return -1;

    // find input coins
    var k = 0;
    while (WalletMath.lessThanOrEqTo(coin_ordered[k].Value, amount)) {
        amount = WalletMath.sub(amount, coin_ordered[k].Value);
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

        // index
        pos = 1 + (x * 34) + 32;
        inputIndex = numStoreInMemory(coin_ordered[x]['Index'].toString(16), 4);
        data.set(hexstring2ab(inputIndex), pos);
    }

    // calc coin_amount
    var coin_amount = 0;
    for (i = 0; i < k + 1; i++) {
        coin_amount = WalletMath.add(coin_amount, coin_ordered[i].Value);
    }

    return {
        amount: coin_amount,
        data: data
    }
};

/**
 * Make state update transaction and get transaction unsigned data.
 * 发起一个状态更新交易。
 *
 *  * 数据格式：
 * 字节            内容
 * 1              type ： 90
 * 1              version  ： 00
 * 1              名字长度
 * 名字实际长度     名字
 * 1              密钥长度
 * 密钥长度       密钥
 * 1              值长度
 * 值得长度       值
 * 33             压缩的公钥
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

    /**
     * data数据拼接：
     */
    var type = "90";
    var version = "00";
    var assetNameLen = numStoreInMemory($namespace.length.toString(16), 0);
    var assetName = ab2hexstring(str2ab($namespace));
    var keyLen = numStoreInMemory($key.length.toString(16), 0);
    var key = ab2hexstring(str2ab($key));
    var valueLen = numStoreInMemory($value.length.toString(16), 0);
    var value = ab2hexstring(str2ab($value));

    var publicKeyXStr = curvePtX.toString('hex');
    var publicKeyYStr = curvePtY.toString('hex');
    var publicKey = "20" + publicKeyXStr + "20" + publicKeyYStr;

    var transactionAttrNum = "00";
    var transactionInputNum = "00";
    var transactionOutputNum = "00";

    return type + version + assetNameLen + assetName +
        keyLen + key + valueLen + value +
        publicKey + transactionAttrNum + transactionInputNum + transactionOutputNum;
};

/**
 * Make issue transaction and get transaction unsigned data.
 * 发起一个发行资产交易和获取交易数据（十六进制）。
 *
 * 数据格式：
 * 字节            内容
 * 1              type ： 01
 * 1              version  ： 00
 * 1              交易属性个数：01
 * 1              交易属性中的用法
 * 8              交易属性中的数据长度
 * 数据实际长度     交易属性中的数据
 * 1              交易输入个数：Web端存0
 * 32             引用交易hash：个数为0时，则无
 * 2              引用输出索引：个数为0时，则无
 * 1              交易输出个数: 01
 * 32             资产ID：个数为0时，则无
 * 8              资产数量：个数为0时，则无
 * 20             资产ProgramHash：个数为0时，则无
 * 1              Program长度：0x01
 * 1              参数长度 parameter
 * 参数实际长度 	  参数：签名
 * 1			  代码长度 code
 * 代码实际长度     代码：公钥
 *
 * @param $issueAssetID
 * @param $issueAmount
 * @param $publicKeyEncoded
 *
 * @returns {string} : TxUnsignedData
 */
Wallet.makeIssueTransaction = function ($issueAssetID, $issueAmount, $publicKeyEncoded) {
    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);
    var myProgramHash = Wallet.getHash(signatureScript);

    ////////////////////////////////////////////////////////////////////////
    // data
    var type = "01";

    // version
    var version = "00";

    /**
     * 自定义属性,attribute
     * @type {string}
     */
    var transactionAttrNum = "01";
    var transactionAttrUsage = "00";
    var transactionAttrData = ab2hexstring(stringToBytes(parseInt(99999999 * Math.random())));
    var transactionAttrDataLen = prefixInteger(Number(transactionAttrData.length / 2).toString(16), 2);

    // Inputs
    var transactionInputNum = "00";

    // Outputs len
    var transactionOutputNum = "01";
    // Outputs[0] AssetID
    var transactionOutputAssetID = ab2hexstring(reverseArray(hexstring2ab($issueAssetID)));
    // Outputs[0] Amount
    num1 = $issueAmount * 100000000;
    var transactionOutputAmount = numStoreInMemory(num1.toString(16), 16);
    // Outputs[0] ProgramHash
    var transactionOutputProgramHash = myProgramHash.toString();

    return type + version +
        transactionAttrNum + transactionAttrUsage + transactionAttrDataLen + transactionAttrData +
        transactionInputNum + transactionOutputNum + transactionOutputAssetID + transactionOutputAmount + transactionOutputProgramHash;
};

/**
 * Make register transaction and get transaction unsigned data.
 * 发起一个D注册资产交易和获取交易数据（十六进制）。
 * 不兼容N
 *
 * 数据格式：
 * 字节            内容
 * 1              type ： 40
 * 1              version  ： 00
 * 1              资产名字长度
 * 名字实际长度   资产名字
 * 1              资产描述长度
 * 描述实际长度   资产描述
 * 1              资产精度 ： 08
 * 1              资产类型  ： 01
 * 1              资产模型类型 ：00
 * 8              资产数量（小端序）：乘以1亿
 * 33             压缩的公钥
 * 20             资产控制人
 * 1              交易属性个数：01
 * 1              交易属性中的用法
 * 8              交易属性中的数据长度
 * 数据实际长度     交易属性中的数据
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
 *
 * @returns {string} : txUnsignedData
 */
Wallet.makeRegisterTransaction_D = function ($assetName, $assetAmount, $publicKeyEncoded) {
    var ecParams = ecurve.getCurveByName('secp256r1');
    var curvePt = ecurve.Point.decodeFrom(ecParams, new Buffer($publicKeyEncoded, "hex"));
    var publicKeyXStr = (curvePt.affineX.toBuffer(32)).toString('hex');
    var publicKeyYStr = (curvePt.affineY.toBuffer(32)).toString('hex');

    /**
     * 数据拼接：
     */
    var type = "40";
    var version = "00";

    var assetNameLen = prefixInteger((Number($assetName.length).toString(16)), 2);
    var assetName = ab2hexstring(stringToBytes($assetName));
    var assetDescLen = assetNameLen;
    var assetDesc = assetName;

    var assetPrecision = "08"; //精度
    var assetType = "01";
    var assetRecordType = "00";
    var assetAmount = numStoreInMemory(($assetAmount * 100000000).toString(16), 16);

    var publicKey = "20" + publicKeyXStr + "20" + publicKeyYStr;
    var programHash = Wallet.getHash(Wallet.createSignatureScript($publicKeyEncoded)).toString();

    /**
     * 自定义属性
     * @type {string}
     */
    var transactionAttrNum = "01";
    var transactionAttrUsage = "00";
    var transactionAttrData = ab2hexstring(stringToBytes(parseInt(99999999 * Math.random())));
    var transactionAttrDataLen = prefixInteger(Number(transactionAttrData.length / 2).toString(16), 2);


    var transactionInputNum = "00";
    //TODO:后续还需要加一些参数
    var transactionOutputNum = "00";
    //TODO:后续还需要加一些参数

    return type + version +
        assetNameLen + assetName + assetDescLen + assetDesc +
        assetPrecision + assetType + assetRecordType + assetAmount +
        publicKey + programHash +
        transactionAttrNum + transactionAttrUsage + transactionAttrDataLen + transactionAttrData +transactionInputNum + transactionOutputNum;
};

/**
 * Make register transaction and get transaction unsigned data.
 * 发起一个N注册资产交易和获取交易数据（十六进制）
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
Wallet.makeRegisterTransaction_N = function ($assetName, $assetAmount, $publicKeyEncoded, $programHash) {
    var ecparams = ecurve.getCurveByName('secp256r1');
    var curvePt = ecurve.Point.decodeFrom(ecparams, new Buffer($publicKeyEncoded, "hex"));
    var curvePtX = curvePt.affineX.toBuffer(32);
    var curvePtY = curvePt.affineY.toBuffer(32);
    var publicKey = Buffer.concat([new Buffer([0x04]), curvePtX, curvePtY]);

    /**
     * 数据拼接：
     */
    var type = "40";
    var version = "00";
    var assetType = "00";
    var assetNameLen = prefixInteger((Number($assetName.length).toString(16)), 2);
    var assetName = ab2hexstring(stringToBytes($assetName));
    var assetAmount = prefixInteger((Number($assetAmount) * 100000000).toString(16), 16);
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
 *  * 数据格式：
 * 字节            内容
 * 文本数据长度    文本数据
 * 1              标识 ： 01
 * 1              结构长度  ： 41
 * 1              数据长度  ：40
 * 40             数据内容
 * 1              协议数据长度
 * 脚本数据长度   签名脚本数据
 *
 * @param $txData
 * @param $sign
 * @param $publicKeyEncoded
 * @return {string}
 * @constructor
 */
Wallet.AddContract = function ($txData, $sign, $publicKeyEncoded) {


    // sign num
    var Num = "01";
    // sign struct len
    var structLen = "41";
    // sign data len
    var dataLen = "40";
    // sign data
    var data = $sign;
    // Contract data len
    var contractDataLen = "23";
    // script data
    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);

    return $txData + Num + structLen + dataLen + data + contractDataLen + signatureScript;
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
 * 数据格式：
 * 字节            内容
 * 1              type ： 80
 * 1              version  ： 00
 * 1              交易属性个数：01
 * 1              交易属性中的用法
 * 8              交易属性中的数据长度
 * 数据实际长度     交易属性中的数据
 * 1              引用交易的输入个数：个数为0时，则无
 * 32             引用交易的hash：个数为0时，则无
 * 2              引用交易输出的索引：个数为0时，则无
 * 1              交易输出类型: 01为全部转账；02位有找零
 * 32             转账资产ID
 * 8              转账资产数量
 * 20             转账资产ProgramHash
 * 32             找零转账资产ID，仅在交易输出类型为02时有
 * 8              找零转账资产数量，仅在交易输出类型为02时有
 * 20             找零转账资产ProgramHash，仅在交易输出类型为02时有
 * 1              Program长度：0x01
 * 1              参数长度 parameter
 * 参数实际长度 	  参数：签名
 * 1			  代码长度 code
 * 代码实际长度     代码：公钥
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

    if (ab2hexstring(ProgramSha256Buffer.slice(0, 4)) !== ab2hexstring(ProgramHash.slice(21, 25))) {
        //address verify failed.
        return -1;
    }

    ProgramHash = ProgramHash.slice(1, 21);

    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);
    var myProgramHash = Wallet.getHash(signatureScript);

    // INPUT CONSTRUCT
    var inputData = Wallet.GetInputData($coin, $Amount);
    if (inputData === -1) return null;
    var inputAmount = inputData.amount;

    // Adjust the accuracy. （调整精度之后的数据）
    var accuracyVal = 100000000;
    var newOutputAmount = WalletMath.mul($Amount, accuracyVal);
    var newInputAmount = WalletMath.sub(WalletMath.mul(inputAmount, accuracyVal), newOutputAmount);

    /**
     * data
     * @type {string}
     */
    var type = "80";
    var version = "00";
    // 自定义属性,Attributes
    var transactionAttrNum = "01";
    var transactionAttrUsage = "00";
    var transactionAttrData = ab2hexstring(stringToBytes(parseInt(WalletMath.mul(99999999, Math.random()))));
    var transactionAttrDataLen = prefixInteger(Number(transactionAttrData.length / 2).toString(16), 2);
    var referenceTransactionData = ab2hexstring(inputData.data);

    var data = type + version +
        transactionAttrNum + transactionAttrUsage + transactionAttrDataLen + transactionAttrData +
        referenceTransactionData;

    // OUTPUT
    var transactionOutputNum = "01"; //无找零
    var transactionOutputAssetID = ab2hexstring(reverseArray(hexstring2ab($coin['AssetId'])));
    var transactionOutputValue = numStoreInMemory(WalletMath.toHex(newOutputAmount), 16);
    var transactionOutputProgramHash = ab2hexstring(ProgramHash);

    if (WalletMath.eq(inputAmount, $Amount)) {
        data += transactionOutputNum + transactionOutputAssetID + transactionOutputValue + transactionOutputProgramHash;
    } else {
        transactionOutputNum = "02"; //有找零

        // Transfer to someone. 发给他人
        data += transactionOutputNum + transactionOutputAssetID + transactionOutputValue + transactionOutputProgramHash;

        // Change to yourself. 找零给自己
        var transactionOutputValue_me = numStoreInMemory(WalletMath.toHex(newInputAmount), 16);
        var transactionOutputProgramHash_me = myProgramHash.toString();
        data += transactionOutputAssetID + transactionOutputValue_me + transactionOutputProgramHash_me;
    }

    return data;
};

/**
 * 数据格式：
 * 字节            内容
 * 1              type ： 02
 * 1              version  ： 00
 * 1              声明长度
 * 声明长度       声明
 * 1              交易属性个数：00
 * 1              交易属性中的用法：个数为0时，则无
 * 8              交易属性中的数据长度：个数为0时，则无
 * 数据实际长度     交易属性中的数据：个数为0时，则无
 * 1              交易输入个数：Web端存0
 * 32             引用交易hash：个数为0时，则无
 * 2              引用输出索引：个数为0时，则无
 * 1              交易输出个数 : 01
 * 32             资产ID：个数为0时，则无
 * 8              资产数量：个数为0时，则无
 * 20             资产ProgramHash：个数为0时，则无
 * 1              Program长度：0x01
 * 1              参数长度 parameter
 * 参数实际长度 	  参数：签名
 * 1			  代码长度 code
 * 代码实际长度     代码：公钥
 *
 *
 * @return {string}
 */
Wallet.ClaimTransaction = function ($claims, $publicKeyEncoded, $toAddress, $Amount) {
    var signatureScript = Wallet.createSignatureScript($publicKeyEncoded);
    var myProgramHash = Wallet.getHash(signatureScript);

    /**
     * data
     * @type {string}
     */
    var type = "02";
    var version = "00";
    var claimLen = numStoreInMemory($claims['claims'].length.toString(16), 2);
    var claim = '';
    for (var k = 0; k < $claims['claims'].length; k++) {
        claim += ab2hexstring(reverseArray(hexstring2ab($claims['claims'][k]['txid'])));
        claim += numStoreInMemory($claims['claims'][k]['vout'].toString(16), 4);
    }
    var attribute = "00";
    var inputs = "00";
    var outputs = "01";
    var output_assetId = ab2hexstring(reverseArray(hexstring2ab($claims['assetid'])));
    var output_amount = numStoreInMemory(parseInt($Amount).toString(16), 16);

    return type + version +
        claimLen + claim +
        attribute +
        inputs +
        outputs + output_assetId + output_amount +
        myProgramHash.toString();
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

/**
 * 生成随机私钥
 *
 * @return {Uint8Array}
 */
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

        // Get PublicKeyEncoded
        var publicKeyEncoded = curvePt.getEncoded(true);

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

    return accounts;
};

/**
 * Analyze the obtained electronic money.
 * 返回计算好的币。
 *
 * @param res
 * @return {Array}
 */
Wallet.analyzeCoins = function (res) {
    if (res.status == 200) {
        var results = res.data.Result;
        var newCoins = [];

        if (results !== null) {
            var coins = [];
            var tmpIndexArr = [];

            for (let i = 0; i < results.length; i++) {
                coins[i] = results[i];
                coins[i].balance = 0;
                coins[i].balanceView = 0;
                coins[i].AssetIDRev = ab2hexstring(reverseArray(hexstring2ab(results[i]['AssetId'])));
                if (results[i].Utxo != null) {
                    for (j = 0; j < results[i].Utxo.length; j++) {
                        coins[i].balance = WalletMath.add(coins[i].balance, results[i].Utxo[j].Value);
                    }
                    coins[i].balanceView = WalletMath.fixView(coins[i].balance);

                }

                tmpIndexArr.push(results[i].AssetName);
            }

            /**
             * Sorting.
             * @type {Array.<*>}
             */
            tmpIndexArr = tmpIndexArr.sort();
            for (i = 0; i < results.length; i++) {
                for (j = 0; j < results.length; j++) {
                    if (tmpIndexArr[i] == results[j].AssetName) {
                        newCoins.push(results[j]);
                    }
                }
            }
        }

        return newCoins;
    } else {
        return [];
    }
};


/**
 *
 * @param $http
 * @param $address
 * @param $host
 * @param $callback
 * @param $callback_dev
 * @constructor
 */
Wallet.GetClaims = function ($http,$address,$host,$callback,$callback_dev) {
    $http({
        method: 'GET',
        url: $host.webapi_host + ':' + $host.webapi_port + '/api/v1/address/get_claims/' + $address
    }).then($callback).catch($callback_dev);
};

/**
 * Get information about user accounts, transactions, etc.
 * 获取用户账户、交易等信息
 *
 * @param $http
 * @param $address
 * @param $host
 * @param $callback
 * @param $callback_dev
 * @constructor
 */
Wallet.GetUnspent = function ($http,$address,$host,$callback,$callback_dev) {
    $http({
        method: 'GET',
        url: $host.restapi_host + ':' + $host.restapi_port + '/api/v1/asset/utxos/' + $address
    }).then($callback).catch($callback_dev);
};

/**
 * Refresh the height of node
 * 刷新节点高度
 *
 * @param $http
 * @param $host
 * @param $callback
 * @param $callback_dev
 * @constructor
 */
Wallet.GetNodeHeight = function ($http,$host,$callback,$callback_dev) {
    $http({
        method: 'GET',
        url: $host.restapi_host + ':' + $host.restapi_port + '/api/v1/block/height?auth_type=getblockheight'
    }).then($callback).catch($callback_dev);
};

/**
 * Initiate a transaction
 * 发起交易
 *
 * @param $http
 * @param $txData
 * @param $host
 * @param $callback
 * @param $callback_dev
 * @constructor
 */
Wallet.SendTransactionData = function ($http,$txData,$host,$callback,$callback_dev) {
    $http({
        method: 'POST',
        url: $host.restapi_host + ':' + $host.restapi_port + '/api/v1/transaction',
        data: '{"Action":"sendrawtransaction", "Version":"1.0.0", "Type":"","Data":"' + $txData + '"}',
        headers: {"Content-Type": "application/json"}
    }).then($callback).catch($callback_dev);
};

Wallet.GetHighChartData = function ($http,$callback,$callback_dev) {

    $http({
        method: 'GET',
        //url:'https://poloniex.com/public?command=returnTradeHistory&currencyPair=BTC_NXT&start=1410158341&end=1410499372'
        url:'http://api.hksy.com/pc/tradeCenter/v1/selectClinchInfoByCoinName?coinName=IPT&payCoinName=HKD&size=1000'
    }).then($callback).catch($callback_dev);
};

