#pragma once

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <stdexcept>
#include <string>
#include <sstream>

#include "common/command_line.h" // beldex/src
#include "common/file.h"         // beldex/src
#include "common/fs.h"           // beldex/src
#include "cryptonote_config.h"   // beldex/src
#include "config.h"

namespace lws
{
   const std::string default_db_subdir = "/light_wallet_server";
   const std::string dir_slash = "/";
  //  std::cout<< std::getenv("HOME");
   const std::string default_db_dir = std::getenv("HOME")+ dir_slash + std::string(cryptonote::DATA_DIRNAME);
  // const std::string default_db_dir = std::string("/home/blockhash")+ dir_slash + CRYPTONOTE_NAME;
   struct options
  {
    const command_line::arg_descriptor<std::string> db_path;
    const command_line::arg_descriptor<std::string> network;

    options()
       : db_path{"db-path", "Folder for LMDB files", default_db_dir + default_db_subdir}
      , network{"network", "<\"main\"|\"dev\"|\"test\"> -Blockchain net type", "main"}
    {}

    void prepare(boost::program_options::options_description& description) const
    {

      command_line::add_arg(description, db_path);
      command_line::add_arg(description, network);
      command_line::add_arg(description, command_line::arg_help);
    }

    void set_network(boost::program_options::variables_map const& args) const
    {
      const std::string net = command_line::get_arg(args, network);
      if (net == "main")
        lws::config::network = cryptonote::MAINNET;
      else if (net == "dev")
        lws::config::network = cryptonote::DEVNET;
      else if (net == "test")
        lws::config::network = cryptonote::TESTNET;
      else
        throw std::runtime_error{"Bad --network value"};
    }
  };
}