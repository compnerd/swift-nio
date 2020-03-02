add_library(CNIOHTTPParser STATIC
  c_nio_http_parser.c)
target_include_directories(CNIOHTTPParser PUBLIC
  include)
