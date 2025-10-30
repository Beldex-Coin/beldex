// #include <boost/filesystem/operations.hpp>
#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/thread/thread.hpp>
#include <boost/filesystem.hpp>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/command_line.h"      //beldex/common
#include "common/util.h"              //beldex/common
#include "config.h"
#include "cryptonote_config.h"        //beldex/src/
#include "db/storage.h"
#include "error.h"
//#include "rpc/client.h"
#include "options.h"
#include "rest_server.h"
#include "scanner.h"

namespace
{
  struct options : lws::options
  {
    const command_line::arg_descriptor<std::string> daemon_rpc;
    // const command_line::arg_descriptor<std::string> daemon_sub;
    const command_line::arg_descriptor<std::vector<std::string>> rest_servers;
    const command_line::arg_descriptor<std::vector<std::string>> admin_rest_servers;
    const command_line::arg_descriptor<std::string> rest_ssl_key;
    const command_line::arg_descriptor<std::string> rest_ssl_cert;
    const command_line::arg_descriptor<std::size_t> rest_threads;
    const command_line::arg_descriptor<std::size_t> scan_threads;
    const command_line::arg_descriptor<std::vector<std::string>> access_controls;
    const command_line::arg_descriptor<bool> external_bind;
    const command_line::arg_descriptor<unsigned> create_queue_max;
    const command_line::arg_descriptor<std::chrono::minutes::rep> rates_interval;
    const command_line::arg_descriptor<unsigned short> log_level;
    const command_line::arg_descriptor<std::string> config_file;

    static std::string get_default_zmq()
    {
      static constexpr const char base[] = "http://127.0.0.1:";
      switch (lws::config::network)
      {
      case cryptonote::network_type::TESTNET:
        return base + std::to_string(cryptonote::config::testnet::RPC_DEFAULT_PORT);
      case cryptonote::network_type::DEVNET:
        return base + std::to_string(cryptonote::config::devnet::RPC_DEFAULT_PORT);
      case cryptonote::network_type::MAINNET:
      default:
        break;
      }
      return base + std::to_string(cryptonote::config::RPC_DEFAULT_PORT);
    }

    options()
      : lws::options()
      , daemon_rpc{"daemon", "[(https|http)://<address>:]<port> for daemon connections", get_default_zmq()}
      // , daemon_sub{"sub", "tcp://address:port or ipc://path of a beldexd OMQ Pub", ""}
      , rest_servers{"rest-server", "[(https|http)://<address>:]<port>[/<prefix>] for incoming connections, multiple declarations allowed"}
      , admin_rest_servers{"admin-rest-server", "[(https|http])://<address>:]<port>[/<prefix>] for incoming admin connections, multiple declarations allowed"}      , rest_ssl_key{"rest-ssl-key", "<path> to PEM formatted SSL key for https REST server", ""}
      , rest_ssl_cert{"rest-ssl-certificate", "<path> to PEM formatted SSL certificate (chains supported) for https REST server", ""}
      , rest_threads{"rest-threads", "Number of threads to process REST connections", 1}
      , scan_threads{"scan-threads", "Maximum number of threads for account scanning", boost::thread::hardware_concurrency()}
      , access_controls{"access-control-origin", "Specify a whitelisted HTTP control origin domain"}
      , external_bind{"confirm-external-bind", "Allow listening for external connections", false}
      , create_queue_max{"create-queue-max", "Set pending create account requests maximum", 10000}
      , rates_interval{"exchange-rate-interval", "Retrieve exchange rates in minute intervals from cryptocompare.com if greater than 0", 0}
      , log_level{"log-level", "Log level [0-4]", 1}
      , config_file{"config-file", "Specify any option in a config file; <name>=<value> on separate lines"}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      static constexpr const char rest_default[] = "https://0.0.0.0:8443";

      lws::options::prepare(description);
      command_line::add_arg(description, daemon_rpc);
      // command_line::add_arg(description, daemon_sub);
      description.add_options()(rest_servers.name, boost::program_options::value<std::vector<std::string>>()->default_value({rest_default}, rest_default), rest_servers.description);
      command_line::add_arg(description, admin_rest_servers);
      command_line::add_arg(description, rest_ssl_key);
      command_line::add_arg(description, rest_ssl_cert);
      command_line::add_arg(description, rest_threads);
      command_line::add_arg(description, scan_threads);
      command_line::add_arg(description, access_controls);
      command_line::add_arg(description, external_bind);
      command_line::add_arg(description, create_queue_max);
      command_line::add_arg(description, rates_interval);
      command_line::add_arg(description, log_level);
      command_line::add_arg(description, config_file);
    }
  };
 struct program
  {
    std::string db_path;
    std::vector<std::string> rest_servers;
    std::vector<std::string> admin_rest_servers;
    lws::rest_server::configuration rest_config;
    std::string daemon_rpc;
    // std::string daemon_sub;
    std::chrono::minutes rates_interval;
    std::size_t scan_threads;
    unsigned create_queue_max;
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options]" << std::endl;
    out << description;
  }

 boost::optional<program> get_program(int argc, char **argv)
 {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
        po::options_description description{"Options"};
        opts.prepare(description);

        po::store(
            po::command_line_parser(argc, argv).options(description).run(), args);
        po::notify(args);
      if (!command_line::is_arg_defaulted(args, opts.config_file))
      {
        boost::filesystem::path config_path{command_line::get_arg(args, opts.config_file)};
        if (!boost::filesystem::exists(config_path))
          MONERO_THROW(lws::error::configuration, "Config file does not exist");

        po::store(
          po::parse_config_file<char>(config_path.string<std::string>().c_str(), description), args
        );
        po::notify(args);
      }
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
        print_help(std::cout);
        return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/
    mlog_set_log_level(command_line::get_arg(args, opts.log_level));

    program prog{
        command_line::get_arg(args, opts.db_path),
        command_line::get_arg(args, opts.rest_servers),
        command_line::get_arg(args, opts.admin_rest_servers),
        lws::rest_server::configuration{
            {command_line::get_arg(args, opts.rest_ssl_key), command_line::get_arg(args, opts.rest_ssl_cert)},
            command_line::get_arg(args, opts.access_controls),
            command_line::get_arg(args, opts.rest_threads),
            command_line::get_arg(args, opts.external_bind)},
        command_line::get_arg(args, opts.daemon_rpc),
        // command_line::get_arg(args, opts.daemon_sub),
        std::chrono::minutes{command_line::get_arg(args, opts.rates_interval)},
        command_line::get_arg(args, opts.scan_threads),
        command_line::get_arg(args, opts.create_queue_max),
    };

    prog.rest_config.threads = std::max(std::size_t(1), prog.rest_config.threads);
    prog.scan_threads = std::max(std::size_t(1), prog.scan_threads);

    if (command_line::is_arg_defaulted(args, opts.daemon_rpc))
        prog.daemon_rpc = options::get_default_zmq()+ "/json_rpc";
    else
      prog.daemon_rpc = prog.daemon_rpc +"/json_rpc";

    lws::daemon_add = prog.daemon_rpc;
    return prog;
  }
  void run(program prog)
  {
    std::signal(SIGINT, [] (int) { lws::scanner::stop(); });
    fs::create_directories(prog.db_path);
    auto disk = lws::db::storage::open(prog.db_path.c_str(), prog.create_queue_max);
    MINFO("Using beldexd RPC at " << prog.daemon_rpc);

    lws::scanner::sync(disk.clone(),prog.daemon_rpc);

    lws::rest_server server{
      epee::to_span(prog.rest_servers), prog.admin_rest_servers, disk.clone(), std::move(prog.rest_config)
    };
    for (const std::string& address : prog.rest_servers)
      MINFO("Listening for REST clients at " << address);
    for (const std::string& address : prog.admin_rest_servers)
      MINFO("Listening for REST admin clients at " << address);

        // blocks until SIGINT
   lws::scanner::run(std::move(disk),prog.daemon_rpc, prog.scan_threads);
    
  }
} // anonymous

int main(int argc, char **argv)
{
    tools::on_startup(); // if it throws, don't use MERROR just print default msg

    try
    {
        boost::optional<program> prog;

        try
        {
            prog = get_program(argc, argv);
        }
        catch (std::exception const &e)
        {
            std::cerr << e.what() << std::endl
                      << std::endl;
            print_help(std::cerr);
            return EXIT_FAILURE;
        }

        if (prog)
            run(std::move(*prog));
    }
    catch (std::exception const &e)
    {
        MERROR(e.what());
        return EXIT_FAILURE;
    }
    catch (...)
    {
        MERROR("Unknown exception");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
