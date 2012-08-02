{
  "targets": [
    {
      "target_name": "pripub",

      "include_dirs": [
        "src",
        "<(node_root_dir)/deps/openssl/openssl/include",
      ],

      "sources": [
        "src/pripub.cc",
      ]
    }
  ]
}
