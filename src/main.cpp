#include <AUI/Platform/Entry.h>
#include <AUI/Curl/AWebsocket.h>
#include <AUI/Thread/AEventLoop.h>
#include <AUI/Logging/ALogger.h>
#include <AUI/Util/kAUI.h>
#include <AUI/Json/AJson.h>
#include <AUI/Curl/ACurlMulti.h>
#include <AUI/Crypt/AHash.h>
#include <AUI/Util/ARandom.h>
#include <ranges>

static constexpr auto LOG_TAG = "obs-websocket-cli";

enum class Opcode {
    HELLO = 0,
    IDENTIFY = 1,
    IDENTIFIED = 2,
    REQUEST = 6,
    RESPONSE = 7,
};

AUI_ENUM_VALUES(Opcode,
                Opcode::HELLO,
                Opcode::IDENTIFY,
                Opcode::IDENTIFIED,
                Opcode::REQUEST,
                Opcode::RESPONSE
                )

class App: public AObject {
public:
    struct Config {
        AString address = "localhost:4455";
        AString action;
        AOptional<AString> password;
    };

    App(Config config): mSocket(_new<AWebsocket>("localhost:4455")), mConfig(std::move(config)) {
        AObject::connect(mSocket->connected, me::onConnected);
        AObject::connect(mSocket->received, me::onReceived);
        AObject::connect(mSocket->fail, me::onFail);
        AObject::connect(mSocket->closeRequested, [&] {
            ALogger::info(LOG_TAG) << "Connection closed";
            mEventLoop.stop();
        });

        AObject::connect(mSocket->websocketClosed, [&](const AString& v) {
            ALogger::info(LOG_TAG) << "Connection closed: " << v;
            mEventLoop.stop();
        });
    }

    void run() {
        ALogger::info(LOG_TAG) << "Connecting to " << mConfig.address;
        ACurlMulti::global() << mSocket;
        mEventLoop.loop();
    }

private:
    _<AWebsocket> mSocket;
    AOptional<AString> mAuthentication;
    Config mConfig;
    AEventLoop mEventLoop;
    ARandom mRandom;

    void onConnected() {
        ALogger::info(LOG_TAG) << "Connected";
    }

    void onReceived(AByteBufferView packet) {
        ALogger::debug(LOG_TAG) << "Received: " << std::string_view(packet.data(), packet.size());
        auto json = AJson::fromBuffer(packet);
        auto opcode = static_cast<Opcode>(json["op"].asInt());
        ALogger::debug(LOG_TAG) << "Received opcode: " << opcode;

        auto& data = json["d"];

        switch (opcode) {
            case Opcode::HELLO: {

                if (mConfig.password) {
                    auto base64secret = AHash::sha256((*mConfig.password + data["authentication"]["salt"].asString()).toUtf8()).toBase64String();
                    mAuthentication = AHash::sha256((base64secret + data["authentication"]["challenge"].asString()).toUtf8()).toBase64String();
                }

                AJson response = {
                        {"rpcVersion", 1}
                };
                if (mAuthentication) {
                    response["authentication"] = *mAuthentication;
                }
                sendCommand(Opcode::IDENTIFY, std::move(response));

                break;
            }
            case Opcode::IDENTIFIED: {
                ALogger::info(LOG_TAG) << "Authenticated";

                sendRequest(mConfig.action);

                break;
            }

            case Opcode::RESPONSE: {
                mEventLoop.stop();
                break;
            }
        }
    }

    void sendCommand(Opcode op, AJson data) {
        AJson json = {
            {"op", static_cast<int>(op)},
            {"d", std::move(data)},
        };
        AByteBuffer buffer;
        buffer << json;
        ALogger::debug(LOG_TAG) << "Sent: " << std::string_view(buffer.data(), buffer.size());
        *mSocket << buffer;
    }

    void sendRequest(const AString& type, AJson data = AJson::Object{}) {
        sendCommand(Opcode::REQUEST, {
            { "requestType", type },
            { "requestId", mRandom.nextUuid().toString() },
            { "requestData", std::move(data) },
        });
    }

    void onFail(ACurl::ErrorDescription ed) {
        ALogger::err(LOG_TAG) << "Error: " << ed.description;
    }
};

void printHelp() {
    std::cout << "obs-websocket-cli\n"
                 "\t--action= \trequestType (i.e. ToggleRecordPause, StartRecord, StopRecord)\n"
                 "\t--address= \tobs address (default is localhost:4455)\n"
                 "\t--password= \tobs websocket password\n";
}

AUI_ENTRY {
    App::Config config;

    for (const auto& arg : args | std::views::drop(1)) {
        if (!arg.startsWith("--")) {
            std::cerr << "invalid argument: " << arg << '\n';
            printHelp();
            return -1;
        }
        auto i = arg.find('=');
        if (i == std::string::npos) {
            std::cerr << "invalid argument: " << arg << '\n';
            printHelp();
            return -1;
        }
        auto key = arg.substr(2, i - 2);
        auto value = arg.substr(i + 1);
        if (key == "action") {
            config.action = std::move(value);
        } else if (key == "address") {
            config.address = std::move(value);
        } else if (key == "password") {
            config.password = std::move(value);
        }
    }

    if (config.action.empty()) {
        std::cerr << "--action is required\n";
        printHelp();
        return -1;
    }

    if (args.size() <= 1) {
        printHelp();
        return -1;
    }

    _new<App>(std::move(config))->run();
    return 0;
};