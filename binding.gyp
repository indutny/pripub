{
  "targets": [
    {
      "target_name": "pripub",
      "dependencies": [ "deps/openssl/openssl.gyp:openssl" ],

      "include_dirs": [
        "src",
        "deps/openssl/openssl/include",
      ],

      "sources": [
        "src/pripub.cc",
      ]
    }
  ]
}
