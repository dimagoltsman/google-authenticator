// A simple authentication application written in HTML
// Copyright (C) 2012 Gerard Braad
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

(function(exports) {
    "use strict";

    var StorageService = function() {
        var setObject = function(key, value) {
            localStorage.setItem(key, JSON.stringify(value));
        };

        var getObject = function(key) {
            var value = localStorage.getItem(key);
            // if(value) return parsed JSON else undefined
            return value && JSON.parse(value);
        };

        var isSupported = function() {
            return typeof (Storage) !== "undefined";
        };

        // exposed functions
        return {
            isSupported: isSupported,
            getObject: getObject,
            setObject: setObject
        };
    };

    exports.StorageService = StorageService;

    // Originally based on the JavaScript implementation as provided by Russell Sayers on his Tin Isles blog:
    // http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/

    var KeyUtilities = function(jsSHA) {

        var dec2hex = function(s) {
            return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
        };

        var hex2dec = function(s) {
            return parseInt(s, 16);
        };

        var base32tohex = function(base32) {
            var base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bits = "";
            var hex = "";

            for (var i = 0; i < base32.length; i++) {
                var val = base32chars.indexOf(base32.charAt(i).toUpperCase());
                bits += leftpad(val.toString(2), 5, '0');
            }

            for (i = 0; i + 4 <= bits.length; i += 4) {
                var chunk = bits.substr(i, 4);
                hex = hex + parseInt(chunk, 2).toString(16);
            }

            return hex;
        };

        var leftpad = function(str, len, pad) {
            if (len + 1 >= str.length) {
                str = new Array(len + 1 - str.length).join(pad) + str;
            }
            return str;
        };

        var generate = function(secret, epoch) {
            var key = base32tohex(secret);

            // HMAC generator requires secret key to have even number of nibbles
            if (key.length % 2 !== 0) {
                key += '0';
            }

            // If no time is given, set time as now
            if(typeof epoch === 'undefined') {
                epoch = Math.round(new Date().getTime() / 1000.0);
            }
            var time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, '0');

            // external library for SHA functionality
            var hmacObj = new jsSHA(time, "HEX");
            var hmac = hmacObj.getHMAC(key, "HEX", "SHA-1", "HEX");

            var offset = 0;
            if (hmac !== 'KEY MUST BE IN BYTE INCREMENTS') {
                offset = hex2dec(hmac.substring(hmac.length - 1));
            }

            var otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) % 1000000 + '';
            return Array(7 - otp.length).join('0') + otp;
        };

        // exposed functions
        return {
            generate: generate
        };
    };

    exports.KeyUtilities = KeyUtilities;

    // ----------------------------------------------------------------------------
    var KeysController = function() {
        var storageService = null,
            keyUtilities = null,
            editingEnabled = false;

        var init = function() {
            storageService = new StorageService();
            keyUtilities = new KeyUtilities(jsSHA);

            // Check if local storage is supported
            if (storageService.isSupported()) {
                if (!storageService.getObject('accounts')) {
                    //addAccount('alice@google.com (demo account)', 'JBSWY3DPEHPK3PXP');
                    storageService.setObject('accounts', []);
                    toggleEdit();
                }

                updateKeys();
                setInterval(timerTick, 1000);
            } else {
                // No support for localStorage
                $('#updatingIn').text("x");
                $('#accountsHeader').text("No Storage support");
            }

            // Bind to keypress event for the input
            $('#addKeyButton').click(function() {
                var name = $('#keyAccount').val();
                var secret = $('#keySecret').val();
                // remove spaces from secret
                secret = secret.replace(/ /g, '');
                if(secret !== '') {
                    addAccount(name, secret);
                    clearAddFields();
                    $.mobile.navigate('#main');
                } else {
                    $('#keySecret').focus();
		}
            });

            $('#addKeyCancel').click(function() {
                clearAddFields();
            });

            var clearAddFields = function() {
                $('#keyAccount').val('');
		        $('#keySecret').val('');
            };

            $('#searchInput').on('keyup', function() {
                updateKeys();
            });

            $('#edit').click(function() { toggleEdit(); });
            $('#export').click(function() { exportAccounts(); });
        };

        var updateKeys = function() {
            var accountList = $('#accounts');
            // Remove all except the first line
            accountList.find("li:gt(0)").remove();

            var searchQuery = ($('#searchInput').val() || '').toLowerCase();

            $.each(storageService.getObject('accounts'), function (index, account) {
                if (searchQuery && account.name.toLowerCase().indexOf(searchQuery) === -1) {
                    return; // skip non-matching accounts
                }

                var key = keyUtilities.generate(account.secret);

                // Construct HTML
                var accName = $('<p>').text(account.name).html();  // print as-is
                var detLink = $('<span class="secret"><h3>' + key + '</h3>' + accName + '</span>');
                var accElem = $('<li data-icon="false">').append(detLink);
                detLink.click(function(e){
                    var element = $(this).find("h3");
                    var code = element.text();
                    var $temp = $('<input>');
                    $('body').append($temp);
                    $temp.val(code).select();
                    document.execCommand('copy');
                    $temp.remove();
                    $('#copy-toast').remove();
                    var toast = $('<div id="copy-toast" class="copy-toast">Copied!</div>');
                    $('body').append(toast);
                    var rect = this.getBoundingClientRect();
                    toast.css({
                        top: (rect.top + window.scrollY - toast.outerHeight() - 8) + 'px',
                        left: (rect.left + rect.width / 2) + 'px'
                    });
                    setTimeout(function() { toast.addClass('show'); }, 10);
                    setTimeout(function () {
                        toast.removeClass('show');
                        setTimeout(function() { toast.remove(); }, 300);
                    }, 1500);
                });
 
                if(editingEnabled) {
                    accElem.attr('draggable', 'true');
                    accElem.attr('data-index', index);

                    var handle = $('<span class="drag-handle">&#8942;&#8942;</span>');
                    accElem.prepend(handle);

                    var delBtn = $('<a class="delete-btn" href="#">&times;</a>');
                    delBtn.click(function(e) { e.preventDefault(); e.stopPropagation(); deleteAccount(index); });
                    accElem.append(delBtn);

                    accElem.on('dragstart', function(e) {
                        e.originalEvent.dataTransfer.effectAllowed = 'move';
                        e.originalEvent.dataTransfer.setData('text/plain', index);
                        $(this).addClass('dragging');
                    });
                    accElem.on('dragend', function() {
                        $(this).removeClass('dragging');
                        $('#accounts li').removeClass('drag-over drag-over-top');
                    });
                    accElem.on('dragover', function(e) {
                        e.preventDefault();
                        e.originalEvent.dataTransfer.dropEffect = 'move';
                        var rect = this.getBoundingClientRect();
                        var mid = rect.top + rect.height / 2;
                        var isTop = e.originalEvent.clientY < mid;
                        $(this).toggleClass('drag-over', !isTop).toggleClass('drag-over-top', isTop);
                    });
                    accElem.on('dragleave', function() {
                        $(this).removeClass('drag-over drag-over-top');
                    });
                    accElem.on('drop', function(e) {
                        e.preventDefault();
                        var fromIndex = parseInt(e.originalEvent.dataTransfer.getData('text/plain'));
                        var toIndex = parseInt($(this).attr('data-index'));
                        if (fromIndex !== toIndex) {
                            moveAccount(fromIndex, toIndex);
                        }
                        $('#accounts li').removeClass('drag-over drag-over-top');
                    });
                }

                // Add HTML element
                accountList.append(accElem);
            });
            accountList.listview().listview('refresh');
        };

        var toggleEdit = function() {
            editingEnabled = !editingEnabled;
            updateKeys();
        };

        var exportAccounts = function() {
            var accounts = JSON.stringify(storageService.getObject('accounts'));
            var blob = new Blob([accounts], {type: 'text/plain;charset=utf-8'});

            saveAs(blob, 'gauth-export.json');
        };

        var moveAccount = function(fromIndex, toIndex) {
            var accounts = storageService.getObject('accounts');
            if (toIndex < 0 || toIndex >= accounts.length) return;
            var item = accounts.splice(fromIndex, 1)[0];
            accounts.splice(toIndex, 0, item);
            storageService.setObject('accounts', accounts);
            updateKeys();
        };

        var deleteAccount = function(index) {
            // Remove object by index
            var accounts = storageService.getObject('accounts');
            accounts.splice(index, 1);
            storageService.setObject('accounts', accounts);

            updateKeys();
        };

        var addAccount = function(name, secret) {
            if(secret === '') {
                // Bailout
                return false;
            }

            // Construct JSON object
            var account = {
                'name': name,
                'secret': secret
            };

            // Persist new object
            var accounts = storageService.getObject('accounts');
            if (!accounts) {
                // if undefined create a new array
                accounts = [];
            }
            accounts.push(account);
            storageService.setObject('accounts', accounts);

            updateKeys();
            toggleEdit();

            return true;
        };

        var timerTick = function() {
            var epoch = Math.round(new Date().getTime() / 1000.0);
            var countDown = 30 - (epoch % 30);
            if (epoch % 30 === 0) {
                updateKeys();
            }
            $('#updatingIn').text(countDown);
        };

        return {
            init: init,
            addAccount: addAccount,
            deleteAccount: deleteAccount
        };
    };

    exports.KeysController = KeysController;

})(typeof exports === 'undefined' ? this['gauth']={} : exports);
