//  Copyright 2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>

#include "net/proto2/compiler/cpp/public/generator.h"
#include "net/proto2/compiler/public/plugin.h"
#include "net/proto2/proto/descriptor.proto.h"
#include "net/proto2/public/descriptor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/protobuf/io/printer.h"
#include "third_party/sealedcomputing/protoc_plugin/annotations.proto.h"

namespace sealed::proto {

namespace {

using ::proto2::Descriptor;
using ::proto2::EnumDescriptor;
using ::proto2::EnumValueDescriptor;
using ::proto2::FieldDescriptor;
using ::proto2::FileDescriptor;
using ::proto2::MethodDescriptor;
using ::proto2::ServiceDescriptor;
using ::proto2::compiler::GeneratorContext;
using ::proto2::compiler::cpp::CppGenerator;
using ::proto2::io::Printer;

class SealedRpcCodeGen : public CppGenerator {
 public:
  bool Generate(const FileDescriptor* file, const std::string& parameter,
                GeneratorContext* generator_context,
                std::string* error) const override;
};

std::string ToUpper(const std::string& str) {
  std::string res(str);
  for (auto c = res.begin(); c != res.end(); ++c) *c = toupper(*c);
  return res;
}

// Returns a header guard derived from the path of the given `file` and
// `suffix`.
std::string HeaderGuard(const FileDescriptor* file, const std::string& suffix) {
  std::string guard = ToUpper(file->name() + suffix);
  std::replace(guard.begin(), guard.end(), '.', '_');
  std::replace(guard.begin(), guard.end(), '-', '_');
  std::replace(guard.begin(), guard.end(), '/', '_');
  std::replace(guard.begin(), guard.end(), '\\', '_');
  return guard;
}

// Prints a namespace either opening '{' or closing '}' with commented name.
void PrintNamespace(bool closing, const FileDescriptor* file, Printer* printer,
                    const std::string& suffix = "") {
  std::string s = file->options().GetExtension(sealed_package);
  if (s.empty()) {
    s = file->package();
  }

  std::vector<std::string> namespaces;
  for (int i = s.find('.'); i != std::string::npos; i = s.find('.')) {
    namespaces.emplace_back(s.substr(0, i));
    s.erase(0, i + 1);
  }
  namespaces.emplace_back(s);

  if (!suffix.empty()) {
    namespaces.emplace_back(suffix);
  }

  if (closing) {
    for (auto it = namespaces.rbegin(); it != namespaces.rend(); ++it) {
      printer->Print("}  // namespace $ns$\n", "ns", *it);
    }

  } else {
    for (const auto& ns : namespaces) {
      printer->Print("namespace $ns$ {\n", "ns", ns);
    }
  }
}

// Returns a (static) map where keys are a FieldDescriptor::type and
// values are (cpp_name, encoder_decoder_name).
// cpp_name is a string denoting the equivalent C++ type.
// encoder_decoder_name is a string denoting the name of the method used by
// sealed::rpc::Encoder/Decoder to encode/decode values of the type.
std::map<FieldDescriptor::Type, std::tuple<std::string, std::string>>*
GetFieldDescriptorTypeMap() {
  static const auto map =
      new std::map<FieldDescriptor::Type, std::tuple<std::string, std::string>>(
          {
              {FieldDescriptor::TYPE_FLOAT, {"float", "F32"}},
              {FieldDescriptor::TYPE_DOUBLE, {"double", "F64"}},
              {FieldDescriptor::TYPE_INT32, {"int32_t", "S32"}},
              {FieldDescriptor::TYPE_INT64, {"int64_t", "S64"}},
              {FieldDescriptor::TYPE_UINT32, {"uint32_t", "U32"}},
              {FieldDescriptor::TYPE_UINT64, {"uint64_t", "U64"}},
              {FieldDescriptor::TYPE_BOOL, {"bool", "Bool"}},
              {FieldDescriptor::TYPE_STRING, {"std::string", "String"}},
              {FieldDescriptor::TYPE_BYTES, {"std::string", "String"}},
          });
  return map;
}

std::string EncoderDecoderTypeName(FieldDescriptor::Type type) {
  auto map = GetFieldDescriptorTypeMap();
  auto it = map->find(type);
  CHECK(it != map->end());  // Crash OK
  return std::get<1>(it->second);
}

bool GetCppTypeName(const FieldDescriptor* field, std::string* cpp_type_name,
                    std::string* error) {
  switch (field->type()) {
    case FieldDescriptor::TYPE_DOUBLE:
    case FieldDescriptor::TYPE_FLOAT:
    case FieldDescriptor::TYPE_INT64:
    case FieldDescriptor::TYPE_UINT64:
    case FieldDescriptor::TYPE_INT32:
    case FieldDescriptor::TYPE_UINT32:
    case FieldDescriptor::TYPE_BOOL:
    case FieldDescriptor::TYPE_STRING:
    case FieldDescriptor::TYPE_BYTES: {
      auto map = GetFieldDescriptorTypeMap();
      auto it = map->find(field->type());
      CHECK(it != map->end());  // Crash OK
      *cpp_type_name = std::get<0>(it->second);
      return true;
    }
    case FieldDescriptor::TYPE_ENUM:
      *cpp_type_name = field->enum_type()->name();
      return true;
    case FieldDescriptor::TYPE_MESSAGE:
      *cpp_type_name = field->message_type()->name();
      return true;
    default:
      *error = absl::StrCat("unsupported field type: ", field->type_name());
      return false;
  }
}

// Prints a field definition inside the enclosing message type definition.
bool PrintFieldDefinition(const FieldDescriptor* field, Printer* printer,
                          std::string* error) {
  std::string cpp_type_name;
  if (!GetCppTypeName(field, &cpp_type_name, error)) {
    return false;
  }
  if (field->is_repeated()) {
    printer->Print("std::vector<$cpp_type_name$> $field_name$ = {};\n",
                   "cpp_type_name", cpp_type_name, "field_name", field->name());
    return true;
  }
  switch (field->type()) {
    case FieldDescriptor::TYPE_DOUBLE:
    case FieldDescriptor::TYPE_FLOAT:
    case FieldDescriptor::TYPE_INT64:
    case FieldDescriptor::TYPE_UINT64:
    case FieldDescriptor::TYPE_INT32:
    case FieldDescriptor::TYPE_UINT32: {
      printer->Print("$cpp_type_name$ $field_name$ = 0;\n", "cpp_type_name",
                     cpp_type_name, "field_name", field->name());
      return true;
    }
    case FieldDescriptor::TYPE_BOOL:
      printer->Print("bool $field_name$ = false;\n", "field_name",
                     field->name());
      return true;
    case FieldDescriptor::TYPE_STRING:
    case FieldDescriptor::TYPE_BYTES:
      printer->Print("std::string $field_name$;\n", "field_name",
                     field->name());
      return true;
    case FieldDescriptor::TYPE_ENUM: {
      std::string default_value =
          absl::StrCat(field->enum_type()->name(),
                       "::", field->default_value_enum()->name());
      printer->Print({{"cpp_type_name", cpp_type_name},
                      {"field_name", field->name()},
                      {"default_value", default_value}},
                     "$cpp_type_name$ $field_name$ = $default_value$;\n");
      return true;
    }
    case FieldDescriptor::TYPE_MESSAGE: {
      printer->Print(
          {{"cpp_type_name", cpp_type_name}, {"field_name", field->name()}},
          "$cpp_type_name$ $field_name$;\n");
      return true;
    }
    default:
      *error = absl::StrCat("unsupported field type: ", field->type_name());
      return false;
  }
}

// Prints a message type definition.
bool PrintMessageDefinition(const Descriptor* message, Printer* printer,
                            std::string* error) {
  printer->Print("struct $message_name$ {\n", "message_name", message->name());
  printer->Indent();
  for (int i = 0; i < message->field_count(); i++) {
    if (!PrintFieldDefinition(message->field(i), printer, error)) {
      return false;
    }
  }
  printer->Outdent();
  printer->Print("};\n\n");
  return true;
}

// Prints an enum definition.
bool PrintEnumDefinition(const EnumDescriptor* enum_descriptor,
                         Printer* printer, std::string* error) {
  if (enum_descriptor->value_count() > UINT8_MAX) {
    *error = "number of values for enum " + enum_descriptor->full_name() +
             " exceeds max limit";
    return false;
  }
  printer->Print("enum class $enum_name$ : uint8_t {\n", "enum_name",
                 enum_descriptor->name());
  printer->Indent();
  for (int i = 0; i < enum_descriptor->value_count(); i++) {
    const EnumValueDescriptor* enum_val_descriptor = enum_descriptor->value(i);
    printer->Print("$enum_value_name$ = $enum_value$,\n", "enum_value_name",
                   enum_val_descriptor->name(), "enum_value",
                   absl::StrCat(enum_val_descriptor->number()));
  }
  printer->Outdent();
  printer->Print("};\n\n");
  return true;
}

bool HasSecrets(const Descriptor* message) {
  for (int i = 0; i < message->field_count(); i++) {
    if (message->field(i)->options().GetExtension(secret)) {
      return true;
    }

    // Protobuf API returns nullptr if the field is not a message type.
    const Descriptor* child_message = message->field(i)->message_type();
    if (child_message != nullptr && HasSecrets(child_message)) {
      return true;
    }
  }
  return false;
}

// Prints the operator overloads for a given message type.
void PrintMessageOperatorOverloadsDeclaration(const Descriptor* message,
                                              Printer* printer) {
  if (HasSecrets(message)) {
    // Do not define comparison operators for messages containing secrets.
    return;
  }
  printer->Print(
      "bool operator==(const $message_name$&, const $message_name$&);\n",
      "message_name", message->name());
  printer->Print(
      "bool operator!=(const $message_name$&, const $message_name$&);\n\n",
      "message_name", message->name());
}

// Prints the function signature for the encoding function for a given message
// type.
void PrintMessageEncoderSignature(const Descriptor* message, Printer* printer) {
  printer->Print(
      "::sealed::wasm::EncodedMessage Encode$message_name$(const "
      "$message_name$& "
      "message)",
      "message_name", message->name());
}

// Prints the function signature for the decoding function for a given message
// type.
void PrintMessageDecoderSignature(const Descriptor* message, Printer* printer) {
  printer->Print(
      "::sealed::wasm::StatusOr<$message_name$> Decode$message_name$(const "
      "::sealed::wasm::EncodedMessage& encoded_message)",
      "message_name", message->name());
}

std::string IteratorName(const FieldDescriptor* field) {
  std::string out = field->full_name();
  std::replace(out.begin(), out.end(), '.', '_');
  return absl::StrCat(out, "_i");
}

// Prints statements that encode a given field.
bool PrintFieldEncoding(const FieldDescriptor* field,
                        const std::string& encoder_name,
                        const std::string& secret_encoder_name,
                        const std::string& enclosing_message_name,
                        Printer* printer, std::string* error) {
  std::map<std::string, std::string> map = {
      {"encoder_name", encoder_name},
      {"full_field_name",
       absl::StrCat(enclosing_message_name, ".", field->name())},
      {"iterator_name", IteratorName(field)},
  };
  if (field->is_repeated()) {
    printer->Print(map, "SC_CHECK($full_field_name$.size() < UINT32_MAX);\n");
    printer->Print(map,
                   "$encoder_name$.StartArray($full_field_name$.size());\n");
    printer->Print(map,
                   "for (uint32_t $iterator_name$ = 0; $iterator_name$ < "
                   "$full_field_name$.size(); $iterator_name$++) {\n");
    printer->Indent();

    absl::StrAppend(&map["full_field_name"],
                    "[", map["iterator_name"], "]");
  }
  switch (field->type()) {
    case FieldDescriptor::TYPE_FLOAT:
    case FieldDescriptor::TYPE_DOUBLE:
    case FieldDescriptor::TYPE_INT64:
    case FieldDescriptor::TYPE_UINT64:
    case FieldDescriptor::TYPE_INT32:
    case FieldDescriptor::TYPE_UINT32:
    case FieldDescriptor::TYPE_BOOL:
    case FieldDescriptor::TYPE_STRING:
    case FieldDescriptor::TYPE_BYTES:
      map.insert({"encoder_type_name", EncoderDecoderTypeName(field->type())});
      printer->Print(
          map, "$encoder_name$.$encoder_type_name$($full_field_name$);\n");
      break;
    case FieldDescriptor::TYPE_ENUM: {
      printer->Print(
          map, "$encoder_name$.U8(static_cast<uint8_t>($full_field_name$));\n");
      break;
    }
    case FieldDescriptor::TYPE_MESSAGE:
      printer->Print(map, "$encoder_name$.StartStruct();\n");
      for (int i = 0; i < field->message_type()->field_count(); i++) {
        std::string encoder_name_to_use = encoder_name;
        if (field->options().GetExtension(secret)) {
          encoder_name_to_use = secret_encoder_name;
        }
        if (!PrintFieldEncoding(field->message_type()->field(i),
                                encoder_name_to_use, secret_encoder_name,
                                map["full_field_name"], printer, error)) {
          return false;
        }
      }
      printer->Print(map, "$encoder_name$.FinishStruct();\n");
      break;
    default:
      *error = absl::StrCat("unsupported field type: ", field->type_name());
      return false;
  }
  if (field->is_repeated()) {
    printer->Outdent();
    printer->Print("}\n");
    printer->Print(map, "$encoder_name$.FinishArray();\n");
  }
  return true;
}

// Prints statements that decode a given field.
void PrintFieldDecodingInternal(std::map<std::string, std::string> map,
                                const std::string& format_string,
                                const std::string& field_full_name,
                                Printer* printer) {
  std::string full_format_string = absl::StrCat(
      "if (!", format_string,
      ") {\n "
      "return ::sealed::wasm::Status(::sealed::wasm::kInvalidArgument, \"Could "
      "not decode RPC ",
      field_full_name,
      "\");\n"
      "}\n");
  printer->Print(map, full_format_string.c_str());
}

// Prints statements that decode a given field.
bool PrintFieldDecoding(const FieldDescriptor* field,
                        const std::string& decoder_name,
                        const std::string& secret_decoder_name,
                        const std::string& enclosing_message_name,
                        Printer* printer, std::string* error) {
  std::map<std::string, std::string> map = {
      {"decoder_name", decoder_name},
      {"full_field_name",
       absl::StrCat(enclosing_message_name, ".", field->name())},
      {"iterator_name", IteratorName(field)},
  };
  if (field->is_repeated()) {
    printer->Print("{\n");
    printer->Indent();
    printer->Print("uint32_t len = 0;\n");
    printer->Print(map, "$decoder_name$.StartArray(&len);\n");
    printer->Print(map, "$full_field_name$.resize(len);\n");
    printer->Print(map,
                   "for (uint32_t $iterator_name$ = 0; $iterator_name$ < len; "
                   "$iterator_name$++) {\n");
    printer->Indent();

    absl::StrAppend(&map["full_field_name"], "[", map["iterator_name"], "]");
  }
  switch (field->type()) {
    case FieldDescriptor::TYPE_FLOAT:
    case FieldDescriptor::TYPE_DOUBLE:
    case FieldDescriptor::TYPE_INT64:
    case FieldDescriptor::TYPE_UINT64:
    case FieldDescriptor::TYPE_INT32:
    case FieldDescriptor::TYPE_UINT32:
    case FieldDescriptor::TYPE_BOOL:
    case FieldDescriptor::TYPE_STRING:
    case FieldDescriptor::TYPE_BYTES:
      map.insert({"decoder_type_name", EncoderDecoderTypeName(field->type())});
      PrintFieldDecodingInternal(
          map, "$decoder_name$.$decoder_type_name$(&($full_field_name$))",
          field->full_name(), printer);
      break;
    case FieldDescriptor::TYPE_ENUM:
      PrintFieldDecodingInternal(map,
                                 "$decoder_name$.U8(reinterpret_cast<uint8_t*>("
                                 "&($full_field_name$)))",
                                 field->full_name(), printer);
      break;
    case FieldDescriptor::TYPE_MESSAGE:
      PrintFieldDecodingInternal(map, "$decoder_name$.StartStruct()",
                                 field->full_name(), printer);
      for (int i = 0; i < field->message_type()->field_count(); i++) {
        std::string decoder_name_to_use = decoder_name;
        if (field->options().GetExtension(secret)) {
          decoder_name_to_use = secret_decoder_name;
        }
        if (!PrintFieldDecoding(field->message_type()->field(i),
                                decoder_name_to_use, secret_decoder_name,
                                map["full_field_name"], printer, error)) {
          return false;
        }
      }
      PrintFieldDecodingInternal(map, "$decoder_name$.FinishStruct()",
                                 field->full_name(), printer);
      break;
    default:
      *error = absl::StrCat("unsupported field type: ", field->type_name());
      return false;
  }
  if (field->is_repeated()) {
    printer->Outdent();
    printer->Print("}\n");
    printer->Print(map, "$decoder_name$.FinishArray();\n");
    printer->Outdent();
    printer->Print("}\n");
  }
  return true;
}

void PrintMessageOperatorOverloadsDefinition(const Descriptor* message,
                                             Printer* printer) {
  if (HasSecrets(message)) {
    // Do not define comparison operators for messages containing secrets.
    return;
  }
  printer->Print(
      "bool operator==(const $message_name$& a, const $message_name$& b) {\n",
      "message_name", message->name());
  printer->Indent();
  for (int i = 0; i < message->field_count(); i++) {
    printer->Print("if (a.$field_name$ != b.$field_name$) { return false; }\n",
                   "field_name", message->field(i)->name());
  }
  printer->Print("return true;\n");
  printer->Outdent();
  printer->Print("}\n\n");

  printer->Print(
      "bool operator!=(const $message_name$& a, const $message_name$& b) {\n",
      "message_name", message->name());
  printer->Indent();
  printer->Print("return !(a==b);");
  printer->Outdent();
  printer->Print("}\n\n");
}

// Prints the definition of the encoding function for a given message type.
bool PrintMessageEncoderDefinition(const Descriptor* message, Printer* printer,
                                   std::string* error) {
  PrintMessageEncoderSignature(message, printer);
  printer->Print(" {\n");
  printer->Indent();
  printer->Print("::sealed::rpc::Encoder public_encoder;\n");
  printer->Print("::sealed::rpc::Encoder secret_encoder;\n");
  for (int i = 0; i < message->field_count(); i++) {
    std::string encoder_name = "public_encoder";
    if (message->field(i)->options().GetExtension(secret)) {
      encoder_name = "secret_encoder";
    }
    if (!PrintFieldEncoding(message->field(i), encoder_name, "secret_encoder",
                            "message", printer, error)) {
      return false;
    }
  }
  printer->Print(
      "return ::sealed::wasm::EncodedMessage(public_encoder.Finish(), "
      "secret_encoder.Finish());\n");
  printer->Outdent();
  printer->Print("}\n\n");
  return true;
}

// Prints the definition of the decoding function for a given message type.
bool PrintMessageDecoderDefinition(const Descriptor* message_descriptor,
                                   Printer* printer, std::string* error) {
  PrintMessageDecoderSignature(message_descriptor, printer);
  printer->Print(" {\n");
  printer->Indent();
  printer->Print("$message_type$ message;\n", "message_type",
                 message_descriptor->name());
  printer->Print(
      "::sealed::rpc::Decoder "
      "public_decoder(encoded_message.public_data);\n");
  printer->Print(
      "::sealed::rpc::Decoder "
      "secret_decoder(encoded_message.secret_data);\n");
  for (int i = 0; i < message_descriptor->field_count(); i++) {
    std::string decoder_name = "public_decoder";
    if (message_descriptor->field(i)->options().GetExtension(secret)) {
      decoder_name = "secret_decoder";
    }
    if (!PrintFieldDecoding(message_descriptor->field(i), decoder_name,
                            "secret_decoder", "message", printer, error)) {
      return false;
    }
  }
  printer->Print(
      "if (!public_decoder.Finish()) {\n return "
      "::sealed::wasm::Status(::sealed::wasm::kInvalidArgument, \"Failed "
      "public_decoder.Finish\");\n}\n");
  printer->Print(
      "if (!secret_decoder.Finish()) {\n return "
      "::sealed::wasm::Status(::sealed::wasm::kInvalidArgument, \"Failed "
      "secret_decoder.Finish\");\n}\n");
  printer->Print("return message;\n");
  printer->Outdent();
  printer->Print("}\n\n");
  return true;
}

// Prints the signature of the client RPC function for a given RPC method.
void PrintClientFunctionSignature(const MethodDescriptor* method,
                                  Printer* printer) {
  std::map<std::string, std::string> map = {
      {"response_message_type", method->output_type()->name()},
      {"request_message_type", method->input_type()->name()},
      {"method_name", method->name()},
  };
  printer->Print(
      map,
      "::sealed::wasm::StatusOr<$response_message_type$> $method_name$(const "
      "$request_message_type$& request)");
}

// Prints the signature of the client socket RPC function for a given RPC
// method.
void PrintClientSocketFunctionSignature(const MethodDescriptor* method,
                                        Printer* printer) {
  std::map<std::string, std::string> map = {
      {"response_message_type", method->output_type()->name()},
      {"request_message_type", method->input_type()->name()},
      {"method_name", method->name()},
  };
  printer->Print(
      map,
      "::sealed::wasm::StatusOr<$response_message_type$> $method_name$(const "
      "$request_message_type$& request, ::sealed::wasm::Socket* socket)");
}

// Prints the definition of the client RPC function for a given RPC method.
void PrintClientFunctionDefinition(const MethodDescriptor* method,
                                   Printer* printer) {
  PrintClientFunctionSignature(method, printer);
  printer->Print(" {\n");
  printer->Indent();

  std::map<std::string, std::string> map = {
      {"response_message_type", method->output_type()->name()},
      {"request_message_type", method->input_type()->name()},
      {"method_name", method->name()},
      {"service_name", method->service()->name()},
  };

  printer->Print(map,
                 "::sealed::wasm::EncodedMessage encoded_request = "
                 "Encode$request_message_type$(request);\n");
  printer->Print("::sealed::wasm::EncodedMessage encoded_response;\n");
  printer->Print(
      map,
      "SC_RETURN_IF_ERROR(::sealed::wasm::SendRpc(\"$service_name$\", "
      "\"$method_name$\", encoded_request, 0, &encoded_response));\n");
  printer->Print(map,
                 "return Decode$response_message_type$(encoded_response);\n");

  printer->Outdent();
  printer->Print("}\n\n");
}

// Prints the definition of the client socket RPC function for a given RPC
// method.
void PrintClientSocketFunctionDefinition(const MethodDescriptor* method,
                                         Printer* printer) {
  PrintClientSocketFunctionSignature(method, printer);
  printer->Print(" {\n");
  printer->Indent();

  std::map<std::string, std::string> map = {
      {"response_message_type", method->output_type()->name()},
      {"request_message_type", method->input_type()->name()},
      {"method_name", method->name()},
      {"service_name", method->service()->name()},
  };

  printer->Print(map,
                 "::sealed::wasm::EncodedMessage encoded_request = "
                 "Encode$request_message_type$(request);\n");
  printer->Print("std::string response;\n");
  printer->Print("::sealed::wasm::SecretByteString response_secret;\n");

  printer->Print(
      map,
      "SC_RETURN_IF_ERROR(::sealed::wasm::SendRpc(\"$service_name$\", "
      "\"$method_name$\", encoded_request.public_data.string(), "
      "encoded_request.secret_data, &response, &response_secret, socket));\n");
  printer->Print(
      map,
      "return "
      "Decode$response_message_type$(::sealed::wasm::EncodedMessage(response, "
      "response_secret));\n");

  printer->Outdent();
  printer->Print("}\n\n");
}

// Prints the signature of the server RPC function for a given RPC method.
void PrintServerFunctionSignature(const MethodDescriptor* method,
                                  Printer* printer) {
  std::map<std::string, std::string> map = {
      {"response_message_type", method->output_type()->name()},
      {"request_message_type", method->input_type()->name()},
      {"method_name", method->name()},
  };
  printer->Print(
      map,
      "extern \"C\" int WASM_EXPORT $method_name$_RPC(int32_t request_len, "
      "int32_t request_secret_len)");
}

// Prints the definition of the server RPC function for a given RPC method.
void PrintServerFunctionDefinition(const MethodDescriptor* method,
                                   Printer* printer) {
  std::map<std::string, std::string> map = {
      {"response_message_type", method->output_type()->name()},
      {"request_message_type", method->input_type()->name()},
      {"method_name", method->name()},
      {"service_name", method->service()->name()}};

  // Forward declare RPC handler.
  printer->Print(map,
                 "::sealed::wasm::StatusOr<$response_message_type$> "
                 "$method_name$(const $request_message_type$& request);\n\n");

  PrintServerFunctionSignature(method, printer);
  printer->Print(" {\n");
  printer->Indent();

  printer->Print(
      map,
      "::sealed::wasm::ByteString encoded_request(request_len);\n"

      "::sealed::wasm::SecretByteString "
      "encoded_request_secret(request_secret_len);\n"

      "biGetRequest(static_cast<void*>(encoded_request.data()), request_len);\n"

      "biGetRequestSecret(static_cast<void*>("
      "encoded_request_secret.data()), request_secret_len);\n"

      "::sealed::wasm::StatusOr<$request_message_type$> request = "
      "Decode$request_message_type$(::sealed::wasm::EncodedMessage(encoded_"
      "request, "
      "encoded_request_secret));\n"

      "if (!request.ok()) {\n"
      "  ::sealed::wasm::SetResponseStatus(request.status());\n"
      "  return true;\n"
      "}\n"

      "auto response = $method_name$(*request);\n"
      "if (!response.ok()) {\n"
      "  ::sealed::wasm::SetResponseStatus(response.status());\n"
      "  return true;\n"
      "}\n"

      "::sealed::wasm::EncodedMessage encoded_response = "
      "Encode$response_message_type$(*response);\n"

      "::sealed::wasm::SetResponse(encoded_response);\n"
      "return true;\n");

  printer->Outdent();
  printer->Print("}\n\n");
}

std::string StripExtension(const std::string& filename) {
  const size_t extension_pos = filename.find_last_of('.');
  if (extension_pos != std::string::npos) {
    return filename.substr(0, extension_pos);
  }
  return filename;
}

inline constexpr std::string_view kCommonHeaderExtension = ".common.h";
inline constexpr std::string_view kCommonSourceExtension = ".common.cc";
inline constexpr std::string_view kClientHeaderExtension = ".client.h";
inline constexpr std::string_view kServerSourceExtension = ".server.cc";

std::string CommonHeaderFilename(const FileDescriptor* file) {
  return absl::StrCat(StripExtension(file->name()), kCommonHeaderExtension);
}

bool GenerateCommonHeaderFile(const FileDescriptor* file, Printer* printer,
                              std::string* error) {
  // Print header guard.
  std::string guard = HeaderGuard(file, "_COMMON_H_");
  printer->Print("#ifndef $guard$\n#define $guard$\n\n", "guard", guard);

  // Print includes.
  printer->Print("#include <string>\n");
  printer->Print(
      "#include \"third_party/sealedcomputing/rpc/encode_decode_lite.h\"\n");
  printer->Print("#include \"third_party/sealedcomputing/wasm3/base.h\"\n");

  // Print includes for imports.
  for (int i = 0; i < file->dependency_count(); i++) {
    const FileDescriptor* dep = file->dependency(i);
    std::string incl = absl::StrCat("\"", CommonHeaderFilename(dep), "\"");
    // This is a bit of a weird hack to not error out if the include file does
    // not exist. This can happen for deps like proto library annotations that
    // do not actually produce any sealed_cc_proto_library code.
    printer->Print(absl::StrCat("#if __has_include(", incl, ")\n"));
    printer->Print(absl::StrCat("#include ", incl, "\n"));
    printer->Print("#endif\n");
  }

  printer->Print("\n");

  // Print namespace opening.
  PrintNamespace(false, file, printer);

  // Print definitions for top-level enums.
  for (int i = 0; i < file->enum_type_count(); i++) {
    if (!PrintEnumDefinition(file->enum_type(i), printer, error)) {
      return false;
    }
  }

  for (int i = 0; i < file->message_type_count(); i++) {
    // Print definitions for top-level messages.
    if (!PrintMessageDefinition(file->message_type(i), printer, error)) {
      return false;
    }

    // Print operator overloads.
    PrintMessageOperatorOverloadsDeclaration(file->message_type(i), printer);

    // Print declarations for encoding and decoding functions.
    PrintMessageEncoderSignature(file->message_type(i), printer);
    printer->Print(";\n");
    PrintMessageDecoderSignature(file->message_type(i), printer);
    printer->Print(";\n\n");
    if (file->service_count() > 0) {
      printer->Print(
          "namespace server {\n"
          "void RegisterRpcHandlers();\n"
          "}  // namespace server\n\n");
    }
  }

  // Print namespace closing and header guard #endif.
  PrintNamespace(true, file, printer);
  printer->Print("\n#endif  // $guard$\n", "guard", guard);
  return true;
}

bool GenerateCommonSourceFile(const FileDescriptor* file,
                              const std::string common_header_file_name,
                              Printer* printer, std::string* error) {
  // Print includes.
  printer->Print("#include <stdint.h>\n");
  printer->Print("#include \"$common_header_file_name$\"\n",
                 "common_header_file_name", common_header_file_name);
  printer->Print("#include \"third_party/sealedcomputing/wasm3/logging.h\"\n");
  printer->Print("\n");

  // Print namespace opening.
  PrintNamespace(false, file, printer);

  // Print definitions for operator overloads and encoding/decoding functions.
  for (int i = 0; i < file->message_type_count(); i++) {
    PrintMessageOperatorOverloadsDefinition(file->message_type(i), printer);

    if (!PrintMessageEncoderDefinition(file->message_type(i), printer, error)) {
      return false;
    }
    if (!PrintMessageDecoderDefinition(file->message_type(i), printer, error)) {
      return false;
    }
  }

  // Print namespace closing.
  PrintNamespace(true, file, printer);
  return true;
}

bool GenerateClientHeaderFile(const FileDescriptor* file,
                              const std::string common_header_file_name,
                              Printer* printer, std::string* error) {
  // Print header guard.
  std::string guard = HeaderGuard(file, "_CLIENT_H_");
  printer->Print("#ifndef $guard$\n#define $guard$\n\n", "guard", guard);

  // Print includes.
  printer->Print("#include \"$common_header_file_name$\"\n",
                 "common_header_file_name", common_header_file_name);
  printer->Print("#include \"third_party/sealedcomputing/wasm3/send_rpc.h\"\n");
  printer->Print("#include \"third_party/sealedcomputing/wasm3/socket.h\"\n");
  printer->Print("\n");

  // Print namespace opening.
  PrintNamespace(false, file, printer, "client");

  if (file->service_count() > 1) {
    *error = "proto file must define at most one sealed RPC service";
    return false;
  }

  // Print inline definitions for client RPC functions.
  for (int i = 0; i < file->service_count(); i++) {
    const ServiceDescriptor* service = file->service(i);
    for (int j = 0; j < service->method_count(); j++) {
      printer->Print("inline ");
      PrintClientFunctionDefinition(service->method(j), printer);
      printer->Print("inline ");
      PrintClientSocketFunctionDefinition(service->method(j), printer);
    }
  }

  // Print namespace closing and header guard #endif.
  PrintNamespace(true, file, printer, "client");
  printer->Print("\n#endif  // $guard$\n", "guard", guard);
  return true;
}

// Print a function for registering all RPC handlers declared in the proto.
void PrintRegisterHandlersFunction(const FileDescriptor* file,
                                   Printer* printer) {
  printer->Print("void RegisterRpcHandlers() {\n");
  for (int i = 0; i < file->service_count(); i++) {
    const ServiceDescriptor* service = file->service(i);
    for (int j = 0; j < service->method_count(); j++) {
      auto method = service->method(j);
      std::map<std::string, std::string> map = {
          {"method_name", method->name()},
          {"service_name", method->service()->name()}};
      printer->Print(map,
                     "  ::sealed::wasm::RegisterRpcHandler(\"$service_name$\", "
                     "\"$method_name$\", $method_name$_RPC);\n");
    }
  }
  printer->Print("}\n\n");
}

bool GenerateServerSourceFile(const FileDescriptor* file,
                              const std::string common_header_file_name,
                              Printer* printer, std::string* error) {
  // Print includes.
  printer->Print("#include \"$common_header_file_name$\"\n",
                 "common_header_file_name", common_header_file_name);
  printer->Print(
      "#include "
      "\"third_party/sealedcomputing/wasm3/enforcer/function_registry.h\"\n");
  printer->Print("\n");

  // Print namespace opening.
  PrintNamespace(false, file, printer, "server");
  printer->Print("\n");

  if (file->service_count() > 1) {
    *error = "proto file must define at most one sealed RPC service";
    return false;
  }

  // Print definitions for server RPC functions.
  for (int i = 0; i < file->service_count(); i++) {
    const ServiceDescriptor* service = file->service(i);
    for (int j = 0; j < service->method_count(); j++) {
      PrintServerFunctionDefinition(service->method(j), printer);
    }
  }

  if (file->service_count() > 0) {
    PrintRegisterHandlersFunction(file, printer);
  }

  // Print namespace closing.
  PrintNamespace(true, file, printer, "server");
  return true;
}

bool SealedRpcCodeGen::Generate(const FileDescriptor* file,
                                const std::string& parameter,
                                GeneratorContext* generator_context,
                                std::string* error) const {
  const std::string base_filename = StripExtension(file->name());

  const std::string common_header_filename = CommonHeaderFilename(file);
  std::unique_ptr<proto2::io::ZeroCopyOutputStream> output_header_stream(
      generator_context->Open(common_header_filename));
  auto header_printer =
      std::make_unique<Printer>(output_header_stream.get(), '$');
  if (!GenerateCommonHeaderFile(file, header_printer.get(), error)) {
    return false;
  }

  std::unique_ptr<proto2::io::ZeroCopyOutputStream> output_source_stream(
      generator_context->Open(
          absl::StrCat(base_filename, kCommonSourceExtension)));
  auto source_printer =
      std::make_unique<Printer>(output_source_stream.get(), '$');
  if (!GenerateCommonSourceFile(file, common_header_filename,
                                source_printer.get(), error)) {
    return false;
  }

  std::unique_ptr<proto2::io::ZeroCopyOutputStream> client_header_stream(
      generator_context->Open(
          absl::StrCat(base_filename, kClientHeaderExtension)));
  auto client_header_printer =
      std::make_unique<Printer>(client_header_stream.get(), '$');
  if (!GenerateClientHeaderFile(file, common_header_filename,
                                client_header_printer.get(), error)) {
    return false;
  }

  std::unique_ptr<proto2::io::ZeroCopyOutputStream> server_source_stream(
      generator_context->Open(
          absl::StrCat(base_filename, kServerSourceExtension)));
  auto server_source_printer =
      std::make_unique<Printer>(server_source_stream.get(), '$');
  if (!GenerateServerSourceFile(file, common_header_filename,
                                server_source_printer.get(), error)) {
    return false;
  }

  return true;
}

}  // namespace

}  // namespace sealed::proto

int main(int argc, char** argv) {
  sealed::proto::SealedRpcCodeGen generator;
  return proto2::compiler::PluginMain(argc, argv, &generator);
}
