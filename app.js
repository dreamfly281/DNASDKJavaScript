var app = angular.module('neow', ['pascalprecht.translate','ui.bootstrap']);

app.config( ['$compileProvider', function( $compileProvider ) {
    $compileProvider.aHrefSanitizationWhitelist(/^\s*(https?|blob|ftp|mailto|tel|file|sms):/);
}]);

app.config(['$translateProvider',function($translateProvider) {
    $translateProvider.useStaticFilesLoader({
        prefix: 'static/i18n/',
        suffix: '.json'
    });

    $translateProvider.preferredLanguage('zh-hans');
    $translateProvider.useSanitizeValueStrategy('escapeParameters');
}]);

app.directive('onReadFile', function ($parse) {
    return {
        restrict: 'A',
        scope: false,
        link: function (scope, element, attrs) {
            var fn = $parse(attrs.onReadFile);

            element.on('change', function (onChangeEvent) {
                var file = (onChangeEvent.srcElement || onChangeEvent.target).files[0];
                var reader = new FileReader();

                reader.onload = function (onLoadEvent) {
                    var Uints = new Uint8Array(reader.result);
                    var db = new window.SQL.Database(Uints);

                    var res = db.exec("SELECT * FROM Key");
                    var passwordHash = new ArrayBuffer();
                    var iv = new ArrayBuffer();
                    var masterKey = new ArrayBuffer();
                    for (i = 0; i < res[0].values.length; i++) {
                        if (res[0].values[i][0] == 'PasswordHash') {
                            passwordHash = res[0].values[i][1];
                        } else if (res[0].values[i][0] == 'IV') {
                            iv = res[0].values[i][1];
                        } else if (res[0].values[i][0] == 'MasterKey') {
                            masterKey = res[0].values[i][1];
                        }
                    }

                    res = db.exec("SELECT * FROM Account");
                    var publicKeyHash = [];
                    var privateKeyEncrypted = [];
                    for (i = 0; i < res[0].values.length; i++) {
                        for (j = 0; j < res[0].values[i].length; j++) {
                            if (j == 0) {
                                publicKeyHash[i] = res[0].values[i][j];
                            }
                            if (j == 1) {
                                privateKeyEncrypted[i] = res[0].values[i][j];
                            }
                        }
                    }

                    var wallet = new Wallet(passwordHash, iv, masterKey, publicKeyHash, privateKeyEncrypted);

                    scope.$apply(function () {
                        fn(scope, {$wallet: wallet});
                    });

                };

                reader.readAsArrayBuffer(file);
            });
        }
    };
});

app.controller('ModalInstanceCtrl', function($scope, $modalInstance, items) {
    $scope.txModify = false;

    if ($scope.txType == '128') {
        $scope.FromAddress = Wallet.toAddress(hexstring2ab(items.fromAddress));

        $scope.ToAddress = Wallet.toAddress(items.tx.outputs[0].scripthash);

        var valueStr = ab2hexstring(reverseArray(items.tx.outputs[0].value));
        $scope.Value = parseInt(valueStr, 16) / 100000000;
        $scope.AssetIDRev = ab2hexstring(reverseArray(items.tx.outputs[0].assetid));
        $scope.AssetID = ab2hexstring(items.tx.outputs[0].assetid);
        $scope.AssetName = "NULL";
        for (i = 0; i < $scope.coins.length; i++) {
            if ($scope.coins[i].AssetId == $scope.AssetIDRev) {
                $scope.AssetName = $scope.coins[i].AssetName;
            }
        }

        // ToAddress Verify failed.
        if (items.toAddress != $scope.ToAddress) {
            console.log("ToAddress verify failed.");
            $scope.txModify = true;
        }

        // Amount Verify failed.
        if (items.amount != $scope.Value) {
            console.log("Amount verify failed.");
            $scope.txModify = true;
        }

        // FromAddress Verify failed.
        if (items.tx.outputs.length == 2) {
            if (Wallet.toAddress(items.tx.outputs[1].scripthash) != $scope.FromAddress) {
                console.log("FromAddress verify failed.");
                $scope.txModify = true;
            }
        }
    } else if ($scope.txType == '2') {
        $scope.ClaimAddress = Wallet.toAddress(hexstring2ab(items.claimAddress));

        var valueStr = ab2hexstring(reverseArray(items.tx.outputs[0].value));
        $scope.Value = parseInt(valueStr, 16);
        $scope.AssetID = ab2hexstring(reverseArray(items.tx.outputs[0].assetid));
        $scope.AssetName = "小蚁币";

        // Amount Verify failed.
        if (items.amount != $scope.Value) {
            console.log("Amount verify failed.");
            $scope.txModify = true;
        }

        // ClaimAddress Verify failed.
        if (Wallet.toAddress(items.tx.outputs[0].scripthash) != $scope.ClaimAddress) {
            console.log("ClaimAddress verify failed.");
            $scope.txModify = true;
        }
    }


    // ok click
    $scope.ok = function () {
        if (!$scope.txModify) {
            if ($scope.walletType == 'externalsignature') {
                $scope.MakeTxAndSend(items.txData);
            } else {
                $scope.SignTxAndSend(items.txData);
            }
        }
        $modalInstance.close();
    };

    // cancel click
    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    }
});

app.controller("SignatureDataCtrl", function($scope,$sce) {
    $scope.txRawData = "";
    $scope.privateKey = "";
    $scope.address = "";
    $scope.signedData = "";

    $scope.notifier = Notifier;
    $scope.notifier.sce = $sce;
    $scope.notifier.scope = $scope;

    $scope.signatureData = function () {
        if ($scope.privateKey.length != 64) {
            $scope.notifier.danger($translate.instant('NOTIFIER_PRIVATEKEY_LENGTH_CHECK_FAILED'));
        } else {
            $scope.signedData = Wallet.signatureData($scope.txRawData, $scope.privateKey);
        }
    }
});
/*
app.controller("hashCalcCtrl", function($scope,$sce) {
	$scope.hashRawData = "";
	$scope.hashedData = "";

	$scope.hashAlgo  = "sha256";
	$scope.hashAlgos = [
		{name:'sha256',algo:'sha256'},
		{name:'sm3',algo:'sm3'},
		{name:'md5',algo:'md5'},
    ];

	$scope.notifier = Notifier;
	$scope.notifier.sce = $sce;
    $scope.notifier.scope = $scope;

	$scope.hashCalc = function() {
		if ( $scope.hashAlgo == 'sha256' ) {
			$scope.hashedData = Wallet.Sha256($scope.hashRawData);
		} else if ( $scope.hashAlgo == 'sm3' ) {
			$scope.hashedData = Wallet.SM3($scope.hashRawData);
		} else if ( $scope.hashAlgo == 'md5' ) {
			$scope.hashedData = Wallet.MD5($scope.hashRawData);
		}
	}
});
*/
app.controller("ToolsCtrl", function($scope,$sce) {
    $scope.wif = "";
    $scope.privateKey = "";
    $scope.publicKey = "";
    $scope.publicKeyEncode = "";
    $scope.script = "";
    $scope.scriptHash = "";
    $scope.address = "";
    $scope.reverse = "";

    $scope.notifier = Notifier;
    $scope.notifier.sce = $sce;
    $scope.notifier.scope = $scope;

    $scope.getReverse = function () {
        if ($scope.reverse.length == 0 || $scope.reverse.length % 2 == 1) {
            $scope.notifier.danger("reverse length check failed.");
        } else {
            $scope.reverse = Wallet.getReverse($scope.reverse);
        }
    };

    $scope.getPrivateKey = function () {
        if ($scope.wif.length != 52) {
            $scope.notifier.danger($translate.instant('NOTIFIER_WIF_LENGTH_CHECK_FAILED'));
        } else {
            var ret = Wallet.getPrivateKeyFromWIF($scope.wif);
            if (ret == -1 || ret == -2) {
                $scope.notifier.danger($translate.instant('NOTIFIER_WIF_DECRYPT_FAILED'));
            } else {
                $scope.privateKey = ret;
            }
        }
    };

    $scope.getPublicKey = function ($encode) {
        if ($scope.privateKey.length != 64) {
            $scope.notifier.danger($translate.instant('NOTIFIER_PRIVATEKEY_LENGTH_CHECK_FAILED'));
        } else {
            $scope.publicKey = Wallet.getPublicKey($scope.privateKey, $encode).toString("hex");
        }
    };

    $scope.getPublicKeyEncoded = function () {
        if ($scope.publicKey.length != 130) {
            $scope.notifier.danger($translate.instant('NOTIFIER_PUBLICKEY_LENGTH_CHECK_FAILED'));
        } else {
            $scope.publicKeyEncode = Wallet.getPublicKeyEncoded($scope.publicKey).toString("hex");
        }
    };

    $scope.getScript = function () {
        if ($scope.publicKeyEncode.length != 66) {
            $scope.notifier.danger($translate.instant('NOTIFIER_PUBLICKEY_ENCODED_LENGTH_CHECK_FAILED'));
        } else {
            $scope.script = "21" + $scope.publicKeyEncode + "ac";
        }
    };

    $scope.getScriptHash = function () {
        if ($scope.script.length != 70) {
            $scope.notifier.danger($translate.instant('NOTIFIER_SCRIPT_LENGTH_CHECK_FAILED'));
        } else {
            $scope.scriptHash = Wallet.getHash($scope.script).toString();
        }
    };

    $scope.getAddress = function () {
        if ($scope.scriptHash.length != 40) {
            $scope.notifier.danger($translate.instant('NOTIFIER_SCRIPTHASH_LENGTH_CHECK_FAILED'));
        } else {
            $scope.address = Wallet.toAddress(hexstring2ab($scope.scriptHash));
        }
    }
});

app.controller("GenerateWalletCtrl", function($scope,$translate,$sce) {
    new Clipboard('.copy-btn')

    $scope.privateKey = $scope.WIFKey = $scope.address = "";
    $scope.createPassword1 = $scope.createPassword2 = "";
    $scope.createType = "fromRandomPrivateKey";
    $scope.objectURL = $scope.objectName = "";

    $scope.styleStringOfCreatePassword1 = $scope.styleStringOfCreatePassword2 = "";
    $scope.isDisplayPassword = false;
    $scope.isDisplayPrivateKey = false;
    $scope.isDisplayAssetId = false;
    $scope.fileDownloaded = false;

    $scope.showCreateWallet = true;
    $scope.showCreateWalletDownload = false;
    $scope.showBtnGenerateWallet = false;

    $scope.notifier = Notifier;
    $scope.notifier.sce = $sce;
    $scope.notifier.scope = $scope;

    $scope.changeCreatePassword1 = function () {
        if ($scope.createPassword1.length >= 8) {
            $scope.styleStringOfCreatePassword1 = "has-success";
        } else {
            $scope.styleStringOfCreatePassword1 = "has-warning";
        }

        if ($scope.isDisplayPassword) {
            if ($scope.createPassword1.length >= 8) {
                $scope.showBtnGenerateWallet = true;
            } else if ($scope.createPassword1.length < 8) {
                $scope.showBtnGenerateWallet = false;
            }
        } else {
            $scope.changeCreatePassword2();
        }
    };

    $scope.changeCreatePassword2 = function () {
        if ($scope.createPassword2.length >= 8 && $scope.createPassword1 == $scope.createPassword2) {
            $scope.styleStringOfCreatePassword2 = "has-success";
            $scope.showBtnGenerateWallet = true;
        } else {
            $scope.styleStringOfCreatePassword2 = "has-warning";
            $scope.showBtnGenerateWallet = false;
        }
    };

    $scope.changeDisplayPassword = function () {
        $scope.isDisplayPassword = !$scope.isDisplayPassword;

        if ($scope.isDisplayPassword) {
            if ($scope.createPassword1.length >= 8) {
                $scope.showBtnGenerateWallet = true;
            } else if ($scope.createPassword1.length < 8) {
                $scope.showBtnGenerateWallet = false;
            }
        } else {
            if ($scope.createPassword2 >= 8 && $scope.createPassword1 == $scope.createPassword2) {
                $scope.showBtnGenerateWallet = true;
            } else {
                $scope.showBtnGenerateWallet = false;
            }
        }
    };

    $scope.changeDisplayPrivateKey = function () {
        $scope.isDisplayPrivateKey = !$scope.isDisplayPrivateKey;
    };

    $scope.downloaded = function () {
        $scope.fileDownloaded = true;
    };

    $scope.nextstep = function () {
        $('#mainTab a[href="#sendTransaction"]').tab('show');
    };

    $scope.generateWalletFileFromRandomPrivateKey = function () {
        if ($scope.createPassword1.length < 8) return;
        if (!$scope.isDisplayPassword) {
            if ($scope.createPassword2.length < 8) return;
            if ($scope.createPassword1 != $scope.createPassword2) return;
        }

        $scope.showCreateWallet = false;
        $scope.showCreateWalletDownload = true;

        $scope.privateKey = ab2hexstring(Wallet.generatePrivateKey());

        /**
         * Get address
         * @type {number}
         */
        var ret = Wallet.GetAccountsFromPrivateKey($scope.privateKey);
        if (ret != -1) {
            $scope.address = ret[0].address;
        }

        var walletBlob = Wallet.createAccount($scope.privateKey, $scope.createPassword1);
        $scope.objectURL = window.URL.createObjectURL(new Blob([walletBlob], {type: 'application/octet-stream'}));
        $scope.objectName = $scope.objectURL.substring($scope.objectURL.lastIndexOf('/') + 1);
        //$scope.objectName = $scope.objectName.replace( /-/g, "" );

        $scope.notifier.success($translate.instant('NOTIFIER_SUCCESS_GENERATE_THE_WALLET') + " <b>wallet--" + $scope.objectName + ".db3</b>");
    };

    $scope.generateWalletFileFromPrivateKey = function () {
        if ($scope.createPassword1.length < 8) return;
        if (!$scope.isDisplayPassword) {
            if ($scope.createPassword2.length < 8) return;
            if ($scope.createPassword1 != $scope.createPassword2) return;
        }

        if ($scope.privateKey.length != 64) {
            $scope.notifier.warning($translate.instant('NOTIFIER_PRIVATEKEY_LENGTH_CHECK_FAILED'));
            return;
        }

        $scope.showCreateWallet = false;
        $scope.showCreateWalletDownload = true;

        var walletBlob = Wallet.createAccount($scope.privateKey, $scope.createPassword1);
        $scope.objectURL = window.URL.createObjectURL(new Blob([walletBlob], {type: 'application/octet-stream'}));
        $scope.objectName = $scope.objectURL.substring($scope.objectURL.lastIndexOf('/') + 1);

        $scope.notifier.success($translate.instant('NOTIFIER_SUCCESS_GENERATE_THE_WALLET') + " <b>wallet--" + $scope.objectName + ".db3</b>");
    };

    $scope.generateWalletFileFromWIFKey = function () {
        if ($scope.createPassword1.length < 8) return;
        if (!$scope.isDisplayPassword) {
            if ($scope.createPassword2.length < 8) return;
            if ($scope.createPassword1 != $scope.createPassword2) return;
        }

        if ($scope.WIFKey.length != 52) {
            $scope.notifier.warning($translate.instant('NOTIFIER_WIF_LENGTH_CHECK_FAILED'));
            return;
    }

        $scope.showCreateWallet = false;
        $scope.showCreateWalletDownload = true;

        $scope.privateKey = Wallet.getPrivateKeyFromWIF($scope.WIFKey);

        var walletBlob = Wallet.createAccount($scope.privateKey, $scope.createPassword1);
        $scope.objectURL = window.URL.createObjectURL(new Blob([walletBlob], {type: 'application/octet-stream'}));
        $scope.objectName = $scope.objectURL.substring($scope.objectURL.lastIndexOf('/') + 1);

        $scope.notifier.success($translate.instant('NOTIFIER_SUCCESS_GENERATE_THE_WALLET') + " <b>wallet--" + $scope.objectName + ".db3</b>");
    };

});

app.controller("WalletCtrl", function($scope,$translate,$http,$sce,$interval,$modal,$filter) {
    $scope.wallet = null;
    $scope.walletType = "fileupload";
    $scope.filePassword = "";
    $scope.privateKeyData = "";
    $scope.WIFKeyData = "";
    $scope.PublicKeyEncodedData = "";

    $scope.txUnsignedData = "";
    $scope.txSignatureData = "";

    $scope.hostSelectIndex = 0;
    $scope.hostInfo = [];

    $scope.version = '';
    $scope.bbsUrl = '';

    $scope.nodeHeight = '0';
    $scope.getNodeHeightLastTime = $filter('date')(new Date(), 'yyyy-MM-dd HH:mm:ss');

    $scope.langSelectIndex = 0;
    $scope.langs = [
        {name: "中文（简体）", lang: "zh-hans"},
        {name: "English", lang: "en"}
    ];

    $scope.downloadSelectIndex = 0;
    $scope.downloads = [
        {name: "Mac"},
        {name: "Windows"},
        {name: "Linux"}
    ];

    $scope.txType = "128"; //默认下拉选项
    $scope.txTypes = [];

    $scope.showOpenWallet = true;
    $scope.showTransaction = false;
    $scope.showBtnUnlock = $scope.showBtnUnlockPrivateKey = $scope.showBtnUnlockWIFKey = $scope.showBtnUnlockExtSig = $scope.requirePass = false;

    $scope.notifier = Notifier;
    $scope.notifier.sce = $sce;
    $scope.notifier.scope = $scope;

    $scope.account = {
        privatekey: "",
        publickeyEncoded: "",
        publickeyHash: "",
        programHash: "",
        address: ""
    };
    $scope.accounts = [];
    $scope.accountSelectIndex = 0;

    $scope.stateUpdate = {
        namespace: "",
        key: "",
        value: ""
    };

    $scope.issueAsset = {
        issueAssetID: "",
        issueAmount: ""
    };

    $scope.registerAsset = {
        assetName: "",
        assetAmount: ""
    };

    $scope.Transaction = {
        ToAddress: "",
        Amount: ""
    };
    $scope.coins = [];
    $scope.coinSelectIndex = 0;

    $scope.claims = {};

    $scope.newAssetId = '';

    $interval(function () {
        var account = $scope.accounts[$scope.accountSelectIndex];
        if (account) {
            if (account.address != "") {
                $scope.getUnspent(account.address);
            }
        }
    }, 30000);

    $scope.init = function () {
        /**
         * 加载node配置:
         */
        $http.get('wallet-conf.json').then(function (data) {
            $scope.hostInfo = data.data.host_info[$scope.langSelectIndex];
            $scope.txTypes = data.data.tx_types[$scope.langSelectIndex];

            $scope.projectName = data.data.project_name;
            $scope.version = data.data.version;
            $scope.domain = data.data.domain;
            $scope.bbsUrl = data.data.bbs_url;

            $scope.connectNode();
        });
    };

    // modal
    $scope.openModal = function () {
        var txData;
        var tx;

        if ($scope.txType == '128') {
            if ($scope.walletType == 'externalsignature') {
                txData = $scope.txUnsignedData;
            } else {
                txData = $scope.transferTransactionUnsigned();
            }
            if (txData == false) return;

            tx = $scope.getTransferTxData(txData);
        } else if ($scope.txType == '2') {
            if ($scope.walletType == 'externalsignature') {
                txData = $scope.txUnsignedData;
            } else {
                txData = $scope.claimTransactionUnsigned();
            }
            if (txData == false) return;

            tx = $scope.getClaimTxData(txData);
        } else {
            return;
        }

        var modalInstance = $modal.open({
            templateUrl: 'myModalContent.html',
            scope: $scope,
            controller: 'ModalInstanceCtrl', // specify controller for modal
            resolve: {
                items: function () {
                    if ($scope.txType == '128') {
                        // transfer transaction
                        return {
                            'txData': txData,
                            'tx': tx,
                            'toAddress': $scope.Transaction.ToAddress,
                            'amount': $scope.Transaction.Amount,
                            'fromAddress': $scope.accounts[$scope.accountSelectIndex].programHash
                        }
                    } else if ($scope.txType == '2') {
                        // claim transaction
                        return {
                            'txData': txData,
                            'tx': tx,
                            'amount': $scope.claims['amount'],
                            'claimAddress': $scope.accounts[$scope.accountSelectIndex].programHash
                        }
                    }
                }
            }
        });
        modalInstance.opened.then(function () {// 模态窗口打开之后执行的函数
        });
        modalInstance.result.then(function (result) {
        }, function (reason) {
        });
    };

    $scope.changeLangSelectIndex = function ($index) {
        $scope.langSelectIndex = $index;
        $translate.use($scope.langs[$index].lang);
        window.localStorage.lang = $scope.langs[$index].lang;

        $http.get('wallet-conf.json').then(function (data) {
            $scope.hostInfo = data.data.host_info[$scope.langSelectIndex];
            $scope.txTypes = data.data.tx_types[$scope.langSelectIndex];
        });
    };

    /**
     * Download desktop wallet file.
     * Download URL example: http://[domain]/downloads/[folderName]/wallet-v1.0.0-[folderName].zip
     *
     * @param $downloadObj
     */
    $scope.changeDownloadSelectIndex = function ($downloadObj) {
        var folderName = $downloadObj.name.toLowerCase();
        window.location.href = "http://" + $scope.domain +
            "/downloads/" + folderName + "/" +
            "wallet-" + $scope.version + "-" + folderName + ".zip";
    };

    $scope.changehostSelectIndex = function ($index) {
        $scope.hostSelectIndex = $index;
        $scope.connectNode();
        if ($scope.accounts[$scope.accountSelectIndex]) {
            $scope.getUnspent($scope.accounts[$scope.accountSelectIndex].address);
        }
    };

    $scope.changeCoinSelectIndex = function ($index) {
        $scope.coinSelectIndex = $index;
    };

    $scope.changeAcountSelectIndex = function ($index) {
        $scope.accountSelectIndex = $index;
        $scope.getUnspent($scope.accounts[$index].address);
        $scope.getClaims($scope.accounts[$index].address);
    };

    $scope.changeTxType = function () {
        // ClaimTransaction
        if ($scope.txType == '2') {
            // get claims
            $scope.getClaims($scope.accounts[$scope.accountSelectIndex].address);
        }
    };

    $scope.openFileDialog = function () {
        document.getElementById('fselector').click();
    };

    $scope.showContent = function ($wallet) {
        $scope.wallet = $wallet;
        $scope.requirePass = true;

        $scope.notifier.info($translate.instant('NOTIFIER_FILE_SELECTED') + document.getElementById('fselector').files[0].name);
    };

    $scope.onFilePassChange = function () {
        if ($scope.filePassword.length > 0) {
            $scope.showBtnUnlock = true;
        } else {
            $scope.showBtnUnlock = false;
        }
    };

    $scope.onPrivateKeyChange = function () {
        if ($scope.privateKeyData.length == 64) {
            $scope.showBtnUnlockPrivateKey = true;
        } else {
            $scope.showBtnUnlockPrivateKey = false;
        }
    };

    $scope.onWIFKeyChange = function () {
        if ($scope.WIFKeyData.length == 52) {
            $scope.showBtnUnlockWIFKey = true;
        } else {
            $scope.showBtnUnlockWIFKey = false;
        }
    };

    $scope.onPublicKeyEncodedChange = function () {
        if ($scope.PublicKeyEncodedData.length == 66) {
            $scope.showBtnUnlockExtSig = true;
        } else {
            $scope.showBtnUnlockExtSig = false;
        }
    };

    $scope.decryptWallet = function () {

        try {
            if ($scope.walletType == "externalsignature") {
                var ret = Wallet.GetAccountsFromPublicKeyEncoded($scope.PublicKeyEncodedData);
                if (ret == -1) {
                    $scope.notifier.danger($translate.instant('NOTIFIER_PUBLICKEY_VERIFY_FAILED'));
                    return;
                }

                $scope.notifier.info($translate.instant('NOTIFIER_SUCCESS_DECRYPT_THE_WALLET'));
                $scope.accounts = ret;

                $scope.showOpenWallet = false;
                $scope.showTransaction = true;

                // get unspent coins
                $scope.getUnspent($scope.accounts[0].address);

            } else if ($scope.walletType == "pasteprivkey") {

                var ret = Wallet.GetAccountsFromPrivateKey($scope.privateKeyData);
                if (ret == -1) {
                    $scope.notifier.danger($translate.instant('NOTIFIER_PRIVATEKEY_LENGTH_CHECK_FAILED'));
                } else if (ret) {
                    $scope.notifier.info($translate.instant('NOTIFIER_SUCCESS_DECRYPT_THE_WALLET'));
                    $scope.accounts = ret;

                    $scope.showOpenWallet = false;
                    $scope.showTransaction = true;

                    // get unspent coins
                    $scope.getUnspent($scope.accounts[0].address);
                }

            } else if ($scope.walletType == "pastewifkey") {

                var ret = Wallet.GetAccountsFromWIFKey($scope.WIFKeyData);
                if (ret == -1) {
                    $scope.notifier.danger($translate.instant('NOTIFIER_WIF_LENGTH_CHECK_FAILED'));
                } else if (ret == -2) {
                    $scope.notifier.danger($translate.instant('NOTIFIER_WIF_VERIFY_FAILED'));
                } else if (ret) {
                    $scope.notifier.info($translate.instant('NOTIFIER_SUCCESS_DECRYPT_THE_WALLET'));
                    $scope.accounts = ret;

                    $scope.showOpenWallet = false;
                    $scope.showTransaction = true;

                    // get unspent coins
                    $scope.getUnspent($scope.accounts[0].address);
                }

            } else if ($scope.walletType == "fileupload") {

                var ret = Wallet.decryptWallet($scope.wallet, $scope.filePassword);
                if (ret == -1) {
                    $scope.notifier.danger($translate.instant('NOTIFIER_PASSWORD_VERIFY_FAILED'));
                } else if (ret == -2) {
                    $scope.notifier.danger($translate.instant('NOTIFIER_ACCOUNTS_VERIFY_FAILED'));
                } else {
                    $scope.notifier.info($translate.instant('NOTIFIER_SUCCESS_DECRYPT_THE_WALLET'));
                    $scope.accounts = ret;

                    $scope.showOpenWallet = false;
                    $scope.showTransaction = true;

                    // get unspent coins
                    $scope.getUnspent($scope.accounts[0].address);
                }

            }
        } catch (e) {
            //$scope.notifier.danger("");
        }
    };

    $scope.catchProblem = function($err){
        console.log(err);
    };

    $scope.getClaims = function ($address) {
        var host = $scope.hostInfo[$scope.hostSelectIndex];
        $scope.claims = {};
        $scope.claims['amount'] = 0;

        Wallet.GetClaims($http,$address,host,(function (res) {
            if (res.status == 200) {
                $scope.claims = res.data;
            }
        }),(function (err) {
            $scope.catchProblem(err);
        }));

    };

    $scope.getUnspent = function ($address) {
        var host = $scope.hostInfo[$scope.hostSelectIndex];

        Wallet.GetUnspent($http,$address, host, (function (res) {
            if (res.status == 200) {
                results = res.data.Result;
                if (results !== null) {
                    $scope.coins = [];
                    var tmpIndexArr = [];
                    var newCoins = [];
                    for (i = 0; i < results.length; i++) {
                        $scope.coins[i] = results[i];
                        $scope.coins[i].balance = 0;
                        if (results[i].Utxo != null) {
                            for (j = 0; j < results[i].Utxo.length; j++) {
                                // results[i].Utxo[j].Value = results[i].Utxo[j].Value / 100000000;
                                results[i].Utxo[j].Value = results[i].Utxo[j].Value;
                                $scope.coins[i].balance = accTools.add($scope.coins[i].balance, results[i].Utxo[j].Value);
                            }
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
                    $scope.coins = newCoins;
                }

                /**
                 * 刷新当前节点高度
                 */
                Wallet.GetNodeHeight($http,host, (function (res) {
                    if (res.status == 200) {
                        if (res.data.Result > 0) {
                            $scope.nodeHeight = res.data.Result;
                            $scope.getNodeHeightLastTime = $filter('date')(new Date(), 'yyyy-MM-dd HH:mm:ss');
                        }
                    }
                }), (function () {
                }));
            }
        }), (function (err) {
            $scope.catchProblem(err);
        }));


    };

    $scope.connectNode = function () {
        var host = $scope.hostInfo[$scope.hostSelectIndex];

        $scope.addressBrowseURL = host.webapi_host + ':' + host.webapi_port;
        $scope.txBrowseURL = host.webapi_host + ':' + host.webapi_port;

        Wallet.GetNodeHeight($http,host,(function (res) {
            if (res.status == 200) {
                if (res.data.Result > 0) {
                    $scope.nodeHeight = res.data.Result;
                    $scope.getNodeHeightLastTime = $filter('date')(new Date(), 'yyyy-MM-dd HH:mm:ss');
                    $scope.notifier.info($translate.instant('NOTIFIER_SUCCESS_CONNECTED_TO_NODE') + " <b>" + $scope.hostInfo[$scope.hostSelectIndex].hostName + "</b>, " + $translate.instant('NOTIFIER_PROVIDED_BY') + " <b>" + $scope.hostInfo[$scope.hostSelectIndex].hostProvider + "</b>, " + $translate.instant('NOTIFIER_NODE_HEIGHT') + " <b>" + res.data.Result + "</b>.");
                } else {
                    $scope.notifier.danger($translate.instant('NOTIFIER_CONNECTED_TO_NODE') + " <b>" + $scope.hostInfo[$scope.hostSelectIndex].hostName + "</b> " + $translate.instant('NOTIFIER_FAILURE'));
                }
            } else {
                $scope.notifier.danger($translate.instant('NOTIFIER_CONNECTED_TO_NODE') + " <b>" + $scope.hostInfo[$scope.hostSelectIndex].hostName + "</b> " + $translate.instant('NOTIFIER_FAILURE'));
            }
        }),(function (res) {
            $scope.notifier.danger($translate.instant('NOTIFIER_CONNECTED_TO_NODE') + " <b>" + $scope.hostInfo[$scope.hostSelectIndex].hostName + "</b> " + $translate.instant('NOTIFIER_FAILURE'));
        }));
    };

    $scope.sendTransactionData = function ($txData) {
        var host = $scope.hostInfo[$scope.hostSelectIndex];

        Wallet.SendTransactionData($http,$txData,host,(function (res) {
            if (res.status == 200) {
                var txhash = reverseArray(hexstring2ab(Wallet.GetTxHash($txData.substring(0, $txData.length - 103 * 2))));

                if (res.data.Error == 0) {
                    // $scope.notifier.success($translate.instant('NOTIFIER_TRANSACTION_SUCCESS_TXHASH') + ab2hexstring(txhash) + " , <a target='_blank' href='" + $scope.txBrowseURL + "'><b>" + $translate.instant('NOTIFIER_CLICK_HERE') + "</b></a>");
                    $scope.notifier.success($translate.instant('NOTIFIER_TRANSACTION_SUCCESS_TXHASH') + ab2hexstring(reverseArray(txhash)));
                } else {
                    $scope.notifier.danger($translate.instant('NOTIFIER_SEND_TRANSACTION_FAILED') + res.data.Error)
                }

                $scope.isDisplayAssetId = true;
                $scope.newAssetId = ab2hexstring(txhash);
            }
        }),(function (err) {
            $scope.catchProblem(err);
        }));

    };

    $scope.MakeTxAndSend = function ($txUnsignedData) {
        if ($txUnsignedData.length > 0 && $scope.txSignatureData.length == 128) {
            var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
            var txRawData = Wallet.AddContract($txUnsignedData, $scope.txSignatureData, publicKeyEncoded);

            $scope.sendTransactionData(txRawData);
        } else {
            $scope.notifier.warning($translate.instant('NOTIFIER_INPUT_DATA_CHECK_FAILED'));
        }
    };

    $scope.stateUpdateTransaction = function () {
        if ($scope.stateUpdate.namespace.length == 0 || $scope.stateUpdate.key.length == 0 || $scope.stateUpdate.value.length == 0) {
            $scope.notifier.warning("Please checked input.");
            return;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var txData = Wallet.makeStateUpdateTransaction($scope.stateUpdate.namespace, $scope.stateUpdate.key, $scope.stateUpdate.value, publicKeyEncoded);

        var privateKey = $scope.accounts[$scope.accountSelectIndex].privatekey;
        var sign = Wallet.signatureData(txData, privateKey);
        var txRawData = Wallet.AddContract(txData, sign, publicKeyEncoded);

        $scope.sendTransactionData(txRawData);
    };

    $scope.issueTransaction = function () {
        if ($scope.issueAsset.issueAssetID.length != 64) {
            $scope.notifier.warning($translate.instant('NOTIFIER_ISSUE_ASSETID_CHECK_FAILED'));
            return;
        }

        if ($scope.issueAsset.issueAmount > parseInt("fffffffff", 16)) {
            $scope.notifier.warning($translate.instant('NOTIFIER_ISSUE_AMOUNT_CHECK_FAILED'));
            return;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var txData = Wallet.makeIssueTransaction($scope.issueAsset.issueAssetID, $scope.issueAsset.issueAmount, publicKeyEncoded);

        var privateKey = $scope.accounts[$scope.accountSelectIndex].privatekey;
        var sign = Wallet.signatureData(txData, privateKey);
        var txRawData = Wallet.AddContract(txData, sign, publicKeyEncoded);

        $scope.sendTransactionData(txRawData);
    };

    $scope.issueTransactionUnsigned = function () {
        if ($scope.issueAsset.issueAssetID.length != 64) {
            $scope.notifier.warning($translate.instant('NOTIFIER_ISSUE_ASSETID_CHECK_FAILED'));
            return;
        }

        if ($scope.issueAsset.issueAmount > parseInt("fffffffff", 16)) {
            $scope.notifier.warning($translate.instant('NOTIFIER_ISSUE_AMOUNT_CHECK_FAILED'));
            return;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var txData = Wallet.makeIssueTransaction($scope.issueAsset.issueAssetID, $scope.issueAsset.issueAmount, publicKeyEncoded);

        $scope.txUnsignedData = txData;
    };

    $scope.registerTransactionUnsigned = function () {
        if ($scope.registerAsset.assetAmount  > parseInt("fffffffff", 16)) {
            $scope.notifier.warning($translate.instant('NOTIFIER_REGISTER_AMOUNT_CHECK_FAILED'));
            return;
        }

        if ($scope.registerAsset.assetName.length > 127) {
            return;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;

        /**
         * 注册资产请求数据构造,lyx
         */
        var txData;
        if ($scope.hostInfo[$scope.hostSelectIndex].node_type === 'DNA') {
            txData = Wallet.makeRegisterTransaction_DNA($scope.registerAsset.assetName, $scope.registerAsset.assetAmount, publicKeyEncoded);
        } else {
            txData = Wallet.makeRegisterTransaction_NEO($scope.registerAsset.assetName, $scope.registerAsset.assetAmount, publicKeyEncoded);
        }

        $scope.txUnsignedData = txData;
    };

    $scope.registerTransaction = function () {
        if ($scope.registerAsset.assetAmount > parseInt("fffffffff", 16)) {
            $scope.notifier.warning($translate.instant('NOTIFIER_REGISTER_AMOUNT_CHECK_FAILED'));
            return;
        }

        if ($scope.registerAsset.assetName.length > 127) {
            return;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;

        /**
         * 注册资产请求数据构造,lyx
         */
        var txData;
        if ($scope.hostInfo[$scope.hostSelectIndex].node_type === 'DNA') {
            txData = Wallet.makeRegisterTransaction_DNA($scope.registerAsset.assetName, $scope.registerAsset.assetAmount, publicKeyEncoded);
        } else {
            txData = Wallet.makeRegisterTransaction_NEO($scope.registerAsset.assetName, $scope.registerAsset.assetAmount, publicKeyEncoded, $scope.accounts[$scope.accountSelectIndex].programHash);
        }

        var privateKey = $scope.accounts[$scope.accountSelectIndex].privatekey;
        var sign = Wallet.signatureData(txData, privateKey);
        var txRawData = Wallet.AddContract(txData, sign, publicKeyEncoded);

        $scope.sendTransactionData(txRawData);
    };

    $scope.transferTransactionUnsigned = function () {
        var reg = /^[0-9]{1,19}([.][0-9]{0,8}){0,1}$/;
        var r = $scope.Transaction.Amount.match(reg);
        if (r == null) {
            $scope.notifier.warning($translate.instant('NOTIFIER_AMOUNT_FORMAT_CHECK_FAILED'));
            return false;
        }

        if ($scope.Transaction.Amount <= 0) {
            $scope.notifier.warning($translate.instant('NOTIFIER_AMOUNT_MUST_GREATER_ZERO'));
            return false;
        }

        if (parseFloat($scope.coins[$scope.coinSelectIndex].balance) < parseFloat($scope.Transaction.Amount)) {
            $scope.notifier.danger($translate.instant('NOTIFIER_NOT_ENOUGH_VALUE') + ", " + $translate.instant('ASSET') + ": " + $scope.coins[$scope.coinSelectIndex].AssetName + ", " + $translate.instant('BALANCE') + ": <b>" + $scope.coins[$scope.coinSelectIndex].balance + "</b>, " + $translate.instant('NOTIFIER_SEND_AMOUNT') + ": <b>" + $scope.Transaction.Amount + "</b>");
            return false;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var txData = Wallet.makeTransferTransaction($scope.coins[$scope.coinSelectIndex], publicKeyEncoded, $scope.Transaction.ToAddress, $scope.Transaction.Amount);
        if (txData == -1) {
            $scope.notifier.danger($translate.instant('NOTIFIER_ADDRESS_VERIFY_FAILED'));
            return false;
        }

        $scope.txUnsignedData = txData;
        return txData;
    };

    $scope.transferTransaction = function () {
        var reg = /^[0-9]{1,19}([.][0-9]{0,8}){0,1}$/;
        var r = $scope.Transaction.Amount.match(reg);
        if (r == null) {
            $scope.notifier.warning($translate.instant('NOTIFIER_AMOUNT_FORMAT_CHECK_FAILED'));
            return false;
        }

        if ($scope.Transaction.Amount <= 0) {
            $scope.notifier.warning($translate.instant('NOTIFIER_AMOUNT_MUST_GREATER_ZERO'));
            return false;
        }

        if (parseFloat($scope.coins[$scope.coinSelectIndex].balance) < parseFloat($scope.Transaction.Amount)) {
            $scope.notifier.danger($translate.instant('NOTIFIER_NOT_ENOUGH_VALUE') + ", " + $translate.instant('ASSET') + ": " + $scope.coins[$scope.coinSelectIndex].AssetName + ", " + $translate.instant('BALANCE') + ": <b>" + $scope.coins[$scope.coinSelectIndex].balance + "</b>, " + $translate.instant('NOTIFIER_SEND_AMOUNT') + ": <b>" + $scope.Transaction.Amount + "</b>");
            return false;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var txData = Wallet.makeTransferTransaction($scope.coins[$scope.coinSelectIndex], publicKeyEncoded, $scope.Transaction.ToAddress, $scope.Transaction.Amount);
        if (txData == -1) {
            $scope.notifier.danger($translate.instant('NOTIFIER_ADDRESS_VERIFY_FAILED'));
            return;
        }

        var privateKey = $scope.accounts[$scope.accountSelectIndex].privatekey;
        var sign = Wallet.signatureData(txData, privateKey);
        var txRawData = Wallet.AddContract(txData, sign, publicKeyEncoded);

        $scope.sendTransactionData(txRawData);
    };

    $scope.claimTransactionUnsigned = function () {
        if ($scope.claims['amount'] <= 0) {
            $scope.notifier.warning($translate.instant('NOTIFIER_AMOUNT_MUST_GREATER_ZERO'));
            return false;
        }

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var txData = Wallet.ClaimTransaction($scope.claims, publicKeyEncoded, $scope.accounts[$scope.accountSelectIndex].address, $scope.claims['amount']);

        $scope.txUnsignedData = txData;
        return txData;
    };

    $scope.claimTransaction = function () {
        var txData = $scope.claimTransactionUnsigned();

        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var privateKey = $scope.accounts[$scope.accountSelectIndex].privatekey;
        var sign = Wallet.signatureData(txData, privateKey);
        var txRawData = Wallet.AddContract(txData, sign, publicKeyEncoded);

        $scope.sendTransactionData(txRawData);

        $scope.claims = {};
        $scope.claims['amount'] = 0;
    };

    $scope.SignTxAndSend = function ($txData) {
        var publicKeyEncoded = $scope.accounts[$scope.accountSelectIndex].publickeyEncoded;
        var privateKey = $scope.accounts[$scope.accountSelectIndex].privatekey;
        var sign = Wallet.signatureData($txData, privateKey);
        var txRawData = Wallet.AddContract($txData, sign, publicKeyEncoded);

        $scope.sendTransactionData(txRawData);
    };

    $scope.getTransferTxData = function ($txData) {
        var ba = new Buffer($txData, "hex");
        var tx = new Transaction();
        var k = 2;

        // Transfer Type
        if (ba[0] != 0x80) return;
        tx.type = ba[0];

        // Version
        tx.version = ba[1];

        // Attributes
        if (ba[k] !== 0) {
            k = k + 2 + ba[k + 2];
        }

        // Inputs
        k = k + 1;
        len = ba[k];
        for (i = 0; i < len; i++) {
            tx.inputs.push({txid: ba.slice(k + 1, k + 33), index: ba.slice(k + 33, k + 35)});
            k = k + 34;
        }

        // Outputs
        k = k + 1;
        len = ba[k];

        for (i = 0; i < len; i++) {
            tx.outputs.push({
                assetid: ba.slice(k + 1, k + 33),
                value: ba.slice(k + 33, k + 41),
                scripthash: ba.slice(k + 41, k + 61)
            });
            k = k + 60;
        }

        return tx;
    };

    $scope.getClaimTxData = function ($txData) {
        var ba = new Buffer($txData, "hex");
        var tx = new ClaimTransaction();

        // Transfer Type
        if (ba[0] != 0x02) return;
        tx.type = ba[0];

        // Version
        tx.version = ba[1];

        // Claim
        var k = 2;
        var len = ba[k];
        for (i = 0; i < len; i++) {
            tx.claims.push({txid: ba.slice(k + 1, k + 33), index: ba.slice(k + 33, k + 35)});
            k = k + 34;
        }

        // Attributes
        k = k + 1;
        len = ba[k];
        for (i = 0; i < len; i++) {
            k = k + 1;
        }

        // Inputs
        k = k + 1;
        len = ba[k];
        // Input len = 0

        // Outputs
        k = k + 1;
        len = ba[k];
        for (i = 0; i < len; i++) {
            tx.outputs.push({
                assetid: ba.slice(k + 1, k + 33),
                value: ba.slice(k + 33, k + 41),
                scripthash: ba.slice(k + 41, k + 61)
            });
            k = k + 60;
        }

        return tx;
    };

});

var Transaction = function Transaction() {
    this.type = 0;
    this.version = 0;
    this.attributes = "";
    this.inputs = [];
    this.outputs = [];
};

var ClaimTransaction = function ClaimTransaction() {
    this.type = 0;
    this.version = 0;
    this.claims = [];
    this.attributes = "";
    this.inputs = [];
    this.outputs = [];
};

var Notifier = {
    show: false,
    class: "",
    icon: "",
    message: "",
    timer: null,
    sce: null,
    scope: null,

    open: function open() {
        this.show = true;
        if (!this.scope.$$phase) this.scope.$apply();
    },

    close: function close() {
        this.show = false;
        if (!this.scope.$$phase) this.scope.$apply();
    },

    warning: function warning(msg) {
        this.class = "alert-warning";
        this.icon = "fa fa-question-circle";
        this.showAlert(this.class, msg);
    },

    info: function info(msg) {
        this.class = "alert-info";
        this.icon = "fa fa-info-circle";
        this.showAlert(this.class, msg);
        this.setTimer();
    },

    danger: function danger(msg) {
        this.class = "alert-danger";
        this.icon = "fa fa-times-circle";
        this.showAlert(this.class, msg);
    },

    success: function success(msg) {
        this.class = "alert-success";
        this.icon = "fa fa-check-circle";
        this.showAlert(this.class, msg);
    },

    showAlert: function showAlert(_class, msg) {
        clearTimeout(this.timer);
        this.class = _class;
        this.message = this.sce.trustAsHtml(msg);
        this.open();
    },

    setTimer: function setTimer() {
        var _this = this;
        clearTimeout(_this.timer);
        _this.timer = setTimeout(function () {
            _this.show = false;
            if (!_this.scope.$$phase) _this.scope.$apply();
        }, 5000);
    }
};
