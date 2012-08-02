#ifndef _SRC_PRIPUB_H_
#define _SRC_PRIPUB_H_

#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace pripub {

using namespace node;

class PriPub : public ObjectWrap {
 public:
  PriPub();
  ~PriPub();

  static void Init(v8::Handle<v8::Object> target);

  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetPublicKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPublicKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPrivateKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> Encode(const v8::Arguments& args);
  static v8::Handle<v8::Value> Decode(const v8::Arguments& args);

  static int PriPassCallback(char* buf, int size, int rwflag, void* u);

 protected:
  RSA* pri_rsa_;
  RSA* pub_rsa_;
};

} // namespace pripub

#endif _SRC_PRIPUB_H_
