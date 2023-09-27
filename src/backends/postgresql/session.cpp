//
// Copyright (C) 2004-2008 Maciej Sobczak, Stephen Hutton
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#define SOCI_POSTGRESQL_SOURCE
#include "soci/soci-platform.h"
#include "soci/postgresql/soci-postgresql.h"
#include "soci/session.h"
#include <libpq/libpq-fs.h> // libpq
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>

using namespace soci;
using namespace soci::details;

namespace // unnamed
{

// helper function for hardcoded queries
void hard_exec(postgresql_session_backend & session_backend,
    PGconn * conn, char const * query, char const * errMsg)
{
    postgresql_result(session_backend, PQexec(conn, query)).check_for_errors(errMsg);
}

} // namespace unnamed

postgresql_session_backend::postgresql_session_backend(
    connection_parameters const& parameters, bool single_row_mode)
    : statementCount_(0), conn_(0)
{
    single_row_mode_ = single_row_mode;

    connect(parameters);
}

void postgresql_session_backend::connect(
    connection_parameters const& parameters)
{
    PGconn* conn = PQconnectdb(parameters.get_connect_string().c_str());
    if (0 == conn || CONNECTION_OK != PQstatus(conn))
    {
        std::string msg = "Cannot establish connection to the database.";
        if (0 != conn)
        {
            msg += '\n';
            msg += PQerrorMessage(conn);
            PQfinish(conn);
        }

        throw soci_error(msg);
    }

    // Increase the number of digits used for floating point values to ensure
    // that the conversions to/from text round trip correctly, which is not the
    // case with the default value of 0. Use the maximal supported value, which
    // was 2 until 9.x and is 3 since it.
    int const version = PQserverVersion(conn);
    hard_exec(*this, conn,
        version >= 90000 ? "SET extra_float_digits = 3"
                         : "SET extra_float_digits = 2",
        "Cannot set extra_float_digits parameter");

    conn_ = conn;
    connectionParameters_ = parameters;
}

postgresql_session_backend::~postgresql_session_backend()
{
    clean_up();
}

bool postgresql_session_backend::is_connected()
{
    // For the connection to work, its status must be OK, but this is not
    // sufficient, so try to actually do something with it, even if it's
    // something as trivial as sending an empty command to the server.
    if ( PQstatus(conn_) != CONNECTION_OK )
        return false;

    postgresql_result(*this, PQexec(conn_, "/* ping */"));

    // And then check it again.
    return PQstatus(conn_) == CONNECTION_OK;
}

void postgresql_session_backend::commit_retain()
{
    throw soci_error("commit_retain: Not implemented!");
}

void postgresql_session_backend::rollback_retain()
{
    throw soci_error("rollback_retain: Not implemented!");
}

void postgresql_session_backend::begin()
{
    // We need to map transaction flags from Firebird/ibase ones
    // to the ones PostgreSQL uses.
    in_transaction_ = true;
    hard_exec(*this, conn_, "BEGIN", "Cannot begin transaction.");
}

void postgresql_session_backend::commit()
{
    hard_exec(*this, conn_, "COMMIT", "Cannot commit transaction.");
    in_transaction_ = false;
    trflags_ = details::trf_none;
}

void postgresql_session_backend::rollback()
{
    hard_exec(*this, conn_, "ROLLBACK", "Cannot rollback transaction.");
    in_transaction_ = false;
    trflags_ = details::trf_none;
}

void postgresql_session_backend::deallocate_prepared_statement(
    const std::string & statementName)
{
    const std::string & query = "DEALLOCATE " + statementName;

    hard_exec(*this, conn_, query.c_str(),
        "Cannot deallocate prepared statement.");
}

bool postgresql_session_backend::get_next_sequence_value(
    session & s, std::string const & sequence, long long & value)
{
    s << "select nextval('" + sequence + "')", into(value);

    return true;
}

void postgresql_session_backend::clean_up()
{
    if (in_transaction_)
    {
        commit();
    }

    if (0 != conn_)
    {
        PQfinish(conn_);
        conn_ = 0;
    }

    trflags_ = details::trf_none;
}

std::string postgresql_session_backend::get_next_statement_name()
{
    char nameBuf[20] = { 0 }; // arbitrary length
    sprintf(nameBuf, "st_%d", ++statementCount_);
    return nameBuf;
}

postgresql_statement_backend * postgresql_session_backend::make_statement_backend()
{
    return new postgresql_statement_backend(*this, single_row_mode_);
}

postgresql_rowid_backend * postgresql_session_backend::make_rowid_backend()
{
    return new postgresql_rowid_backend(*this);
}

postgresql_blob_backend * postgresql_session_backend::make_blob_backend()
{
    return new postgresql_blob_backend(*this);
}

void postgresql_session_backend::stop_event_listener()
{

}

bool postgresql_session_backend::start_event_listener()
{
    return false;
}

void trigger_events(std::map<std::string, size_t>& outEvents)
{
    SOCI_UNUSED(outEvents);
}

int postgresql_session_backend::set_forced_writes(const std::string& server, const std::string& user, const std::string& pass, const std::string& db_file, bool bSync)
{
    SOCI_UNUSED(server);
    SOCI_UNUSED(user);
    SOCI_UNUSED(pass);
    SOCI_UNUSED(db_file);
    SOCI_UNUSED(bSync);

    return -1;
}

int postgresql_session_backend::set_reserve_space(const std::string& server, const std::string& user, const std::string& pass, const std::string& db_file)
{
    SOCI_UNUSED(server);
    SOCI_UNUSED(user);
    SOCI_UNUSED(pass);
    SOCI_UNUSED(db_file);

    return -1;
}