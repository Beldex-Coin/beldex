#include <iostream>
#include <string_view>
#include <oxenc/hex.h>
#include <oxenc/bt_serialize.h>

using namespace oxenc;
using namespace std::literals;

const std::string POS_TAG_VRF_PROOF     = "p";
const std::string POS_TAG_PUB_KEY = "k";

int main() {
    // Simulate a Bencode dictionary: d1:k32:ABCDEFGHIJKLMNOPQRSTUVWX1234567890121:p5:proofe
    bt_dict data              = {};
    data[POS_TAG_VRF_PROOF] = "proof";  // 5-byte string
    data[POS_TAG_PUB_KEY] = std::string(32, 'A');  // 32-byte string of 'A'

    // Serialize to msgpack-style buffer
    std::string serialized_data = bt_serialize(data);  // normally m.data[0]

    // Use dict consumer to parse
    bt_dict_consumer consumer{serialized_data};

    if (consumer.skip_until(POS_TAG_VRF_PROOF)) {
        auto proof = consumer.consume_string_view();
        std::cout << "Parsed proof: " << proof << "\n";
    } else {
        std::cout << "Missing tag: " << POS_TAG_VRF_PROOF << "\n";
    }

    if (consumer.skip_until(POS_TAG_PUB_KEY)) {
        auto key = consumer.consume_string_view();
        std::cout << "Parsed key of size: " << key.size() << "\n";
    } else {
        std::cout << "Missing tag: " << POS_TAG_PUB_KEY << "\n";
    }

    return 0;
}
