(def is-windows
  (not (nil? (string/find "\\" (dyn :syspath)))))

(declare-project
  :name "openssl")

(declare-native
  :name "openssl"
  :source @["openssl.c"]
  :lflags (if
            is-windows
            ["libcrypto.lib"
             "ws2_32.lib"
             "crypt32.lib"
             "advapi32.lib"
             "user32.lib"
             "gdi32.lib"]
            ["-lcrypto"]))
