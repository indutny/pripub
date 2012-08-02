#include "pripub.h"

#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define THROW_OPENSSL_ERROR(msg)\
    {\
      char err[120];\
      ERR_error_string(ERR_get_error(), err);\
      return scope.Close(ThrowException(String::Concat(\
          String::New(msg), String::New(err))));\
    }

namespace pripub {

using namespace v8;
using namespace node;

static Persistent<String> onpassword_sym;

PriPub::PriPub() : pri_rsa_(NULL), pub_rsa_(NULL) {
}


PriPub::~PriPub() {
  if (pri_rsa_ != NULL) RSA_free(pri_rsa_);
  if (pub_rsa_ != NULL) RSA_free(pub_rsa_);
}


int PriPub::PriPassCallback(char* buf, int size, int rwflag, void* u) {
  HandleScope scope;
  PriPub* p = reinterpret_cast<PriPub*>(u);

  Handle<Value> argv[0];
  Handle<Value> result = MakeCallback(p->handle_, onpassword_sym, 0, argv);

  if (!Buffer::HasInstance(result)) {
    return 0;
  }

  char* in = Buffer::Data(result.As<Object>());
  int in_size = Buffer::Length(result.As<Object>());

  if (in_size > size) in_size = size;

  memcpy(buf, in, in_size);

  return in_size;
}


Handle<Value> PriPub::New(const Arguments& args) {
  HandleScope scope;

  PriPub* p = new PriPub();

  p->Wrap(args.Holder());

  return scope.Close(args.This());
}


Handle<Value> PriPub::SetPublicKey(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
    return scope.Close(ThrowException(String::New(
        "First argument should be buffer")));
  }

  PriPub* p = ObjectWrap::Unwrap<PriPub>(args.This());

  Handle<Object> key = args[0].As<Object>();

  // Put keys into buffers
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == NULL) abort();
  if (BIO_write(bio, Buffer::Data(key), Buffer::Length(key)) <= 0) {
    BIO_free_all(bio);
    return scope.Close(ThrowException(String::New(
        "Failed to write into BIO buffer")));
  }

  p->pub_rsa_ = PEM_read_bio_RSA_PUBKEY(bio, NULL, 0, NULL);
  if (p->pub_rsa_ == NULL) {
    BIO_free_all(bio);
    THROW_OPENSSL_ERROR("Failed to read Public RSA key from BIO buffer: ")
  }

  return scope.Close(Null());
}


Handle<Value> PriPub::GetPublicKey(const Arguments& args) {
  HandleScope scope;

  PriPub* p = ObjectWrap::Unwrap<PriPub>(args.This());

  if (p->pri_rsa_ == NULL) {
    return scope.Close(ThrowException(String::New(
        "Private key should be loaded first")));
  }

  BIO* bio = BIO_new(BIO_s_mem());

  if (PEM_write_bio_RSA_PUBKEY(bio, p->pri_rsa_) <= 0) {
    BIO_free_all(bio);
    THROW_OPENSSL_ERROR("Failed to read Public RSA key from Private key ")
  }

  char tmp[1024* 32];
  int read = BIO_read(bio, tmp, sizeof(tmp));
  BIO_free_all(bio);

  Buffer* result = Buffer::New(tmp, read);

  return scope.Close(result->handle_);
}


Handle<Value> PriPub::SetPrivateKey(const Arguments& args) {
  HandleScope scope;

  PriPub* p = ObjectWrap::Unwrap<PriPub>(args.This());

  if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
    return scope.Close(ThrowException(String::New(
        "First argument should be buffer")));
  }

  Handle<Object> key = args[0].As<Object>();

  // Put keys into buffers
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == NULL) abort();
  if (BIO_write(bio, Buffer::Data(key), Buffer::Length(key)) <= 0) {
    BIO_free_all(bio);
    return scope.Close(ThrowException(String::New(
        "Failed to write into BIO buffer")));
  }

  p->pri_rsa_ = PEM_read_bio_RSAPrivateKey(bio,
                                           NULL,
                                           PriPub::PriPassCallback,
                                           p);
  if (p->pri_rsa_ == NULL) {
    char err[120];
    BIO_free_all(bio);
    ERR_error_string(ERR_get_error(), err);
    return scope.Close(ThrowException(String::Concat(
        String::New("Failed to read Private RSA key from BIO buffer: "),
        String::New(err))));
  }

  return scope.Close(Null());
}


Handle<Value> PriPub::Encode(const Arguments& args) {
  HandleScope scope;
  PriPub* p = ObjectWrap::Unwrap<PriPub>(args.This());

  if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
    return scope.Close(ThrowException(String::New(
        "First argument should be buffer")));
  }

  if (p->pub_rsa_ == NULL) {
    return scope.Close(ThrowException(String::New(
        "Public key should be specified before using this function")));
  }

  BIO* bio = BIO_new(BIO_s_mem());

  char* in = Buffer::Data(args[0].As<Object>());
  size_t in_bytes = Buffer::Length(args[0].As<Object>());

  // Get key size
  int key_size = RSA_size(p->pub_rsa_);
  unsigned char* tmp = new unsigned char[key_size];
  int bytes = 0;

  for (size_t i = 0; i < in_bytes;) {
    int to_write = in_bytes - i;

    // Max size = key_size - 11 for RSA_PKCS1_PADDING
    if (to_write > key_size - 11) {
      to_write = key_size - 11;
    }

    // Encrypt bytes
    int written = RSA_public_encrypt(to_write,
                                     reinterpret_cast<const unsigned char*>(in),
                                     tmp,
                                     p->pub_rsa_,
                                     RSA_PKCS1_PADDING);
    if (written < 0) {
      delete[] tmp;
      BIO_free_all(bio);
      THROW_OPENSSL_ERROR("Failed to encrypt data: ")
    }

    // Put bytes into bio
    BIO_write(bio, tmp, written);

    // Increment offsets
    bytes += written;
    i += to_write;
    in += to_write;
  }
  delete[] tmp;

  Buffer* result = Buffer::New(bytes);
  if (BIO_read(bio, Buffer::Data(result), bytes) <= 0) {
    BIO_free_all(bio);
    return scope.Close(ThrowException(String::New(
        "Failed to read encrypted data from buffer")));
  }

  BIO_free_all(bio);

  return scope.Close(result->handle_);
}


Handle<Value> PriPub::Decode(const Arguments& args) {
  HandleScope scope;
  PriPub* p = ObjectWrap::Unwrap<PriPub>(args.This());

  if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
    return scope.Close(ThrowException(String::New(
        "First argument should be buffer")));
  }

  if (p->pri_rsa_ == NULL) {
    return scope.Close(ThrowException(String::New(
        "Private key should be specified before using this function")));
  }

  BIO* bio = BIO_new(BIO_s_mem());

  char* in = Buffer::Data(args[0].As<Object>());
  size_t in_bytes = Buffer::Length(args[0].As<Object>());

  // Get key size
  int key_size = RSA_size(p->pub_rsa_);
  unsigned char* tmp = new unsigned char[key_size];
  int bytes = 0;

  for (size_t i = 0; i < in_bytes;) {
    int to_write = in_bytes - i;

    if (to_write > key_size) {
      to_write = key_size;
    }

    // Encrypt bytes
    int written = RSA_private_decrypt(to_write,
                                     reinterpret_cast<const unsigned char*>(in),
                                     tmp,
                                     p->pri_rsa_,
                                     RSA_PKCS1_PADDING);
    if (written < 0) {
      delete[] tmp;
      BIO_free_all(bio);
      THROW_OPENSSL_ERROR("Failed to decrypt data: ")
    }

    // Put bytes into bio
    BIO_write(bio, tmp, written);

    // Increment offsets
    bytes += written;
    i += to_write;
    in += to_write;
  }
  delete[] tmp;

  Buffer* result = Buffer::New(bytes);
  if (BIO_read(bio, Buffer::Data(result), bytes) <= 0) {
    BIO_free_all(bio);
    return scope.Close(ThrowException(String::New(
        "Failed to read decrypted data from buffer")));
  }

  BIO_free_all(bio);

  return scope.Close(result->handle_);
}


void PriPub::Init(v8::Handle<v8::Object> target) {
  HandleScope scope;

  // Init OpenSSL
  OpenSSL_add_all_algorithms();

  // XXX: Seed random generator

  onpassword_sym = Persistent<String>::New(String::New("onpassword"));

  Local<FunctionTemplate> t = FunctionTemplate::New(PriPub::New);

  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("PriPub"));

  NODE_SET_PROTOTYPE_METHOD(t, "getPublicKey", PriPub::GetPublicKey);
  NODE_SET_PROTOTYPE_METHOD(t, "setPublicKey", PriPub::SetPublicKey);
  NODE_SET_PROTOTYPE_METHOD(t, "setPrivateKey", PriPub::SetPrivateKey);
  NODE_SET_PROTOTYPE_METHOD(t, "encode", PriPub::Encode);
  NODE_SET_PROTOTYPE_METHOD(t, "decode", PriPub::Decode);

  target->Set(String::NewSymbol("PriPub"), t->GetFunction());
}

NODE_MODULE(pripub, PriPub::Init)

} // namespace pripub
