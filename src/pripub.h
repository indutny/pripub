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

  static void* PrivateKeyWorker(void* arg);
  static void PasswordCallback(uv_async_t* handle, int status);
  static void LoadCallback(uv_async_t* handle, int status);

  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetPublicKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPublicKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPrivateKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetKeyPassword(const v8::Arguments& args);
  static v8::Handle<v8::Value> Encrypt(const v8::Arguments& args);
  static v8::Handle<v8::Value> Decrypt(const v8::Arguments& args);

  static int PasswordCallback(char* buf, int size, int rwflag, void* u);

 protected:
  uv_async_t password_cb_;
  uv_async_t load_cb_;

  uv_sem_t password_sem_;

  pthread_t pri_thread_;
  BIO* pri_bio_;
  char pri_pass_[1024];
  int pri_pass_size_;
  int pri_err_;

  RSA* pri_rsa_;
  RSA* pub_rsa_;
};

} // namespace pripub

#endif _SRC_PRIPUB_H_
