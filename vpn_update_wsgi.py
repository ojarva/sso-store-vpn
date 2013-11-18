from openvpn_status_parser import OpenVPNStatusParser
import random
import redis
import time
import datetime
import re
from config import Config
from instrumentation import *
import _mysql

class VPNUpdate:
    def __init__(self, server_hostname):
        self._db = None
        self.server_hostname = server_hostname
        self.config = Config()
        self.redis = redis.Redis(host=self.config.get("redis-hostname"), port=self.config.get("redis-port"), db=self.config.get("redis-db"))

    @property
    def db(self):
        if self._db:
            return self._db
        self._db = _mysql.connect(self.config.get("mysql-hostname"), self.config.get("mysql-username"), self.config.get("mysql-password"), self.config.get("mysql-database"))
        return self._db

    @classmethod
    def escape(cls, string):
        if string is None:
            return "null"
        return "'"+_mysql.escape_string(str(string))+"'"

    @timing("vpn.update.session.open")
    def open_session(self, username, cert_name, local_ip, remote_ip, start_time, end_time_real, bytes_in, bytes_out):
        statsd.incr("vpn.update.session.open")
        now = datetime.datetime.now()

        self.db.query("UPDATE vpn_per_device SET end_time_real=%s WHERE cert_name=%s AND end_time_real is NULL AND server_hostname=%s" % (self.escape(now), self.escape(cert_name), self.escape(self.server_hostname)))
        self.db.store_result()
        self.db.query("INSERT INTO vpn_per_device VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)" %  (self.escape(username), self.escape(cert_name), self.escape(local_ip), self.escape(remote_ip), self.escape(self.server_hostname), self.escape(start_time), self.escape(now), self.escape(end_time_real), self.escape(bytes_in), self.escape(bytes_out), self.escape(now)))
        self.db.store_result()
        self.redis.rpush("ip-resolve-queue", local_ip.split(":")[0])
        self.redis.rpush("ip-resolve-queue", remote_ip.split(":")[0])

    @timing("vpn.update.session.close")
    def close_session(self, cert_name, end_time_real):
        statsd.incr("vpn.update.session.close")
        now = datetime.datetime.now()
        if end_time_real is None:
            end_time_real = now
        redis_key_prefix = "openvpn-update-tmp-%s-%s-" % (self.server_hostname, cert_name)
        bytes_in, bytes_out, known_connected = self.redis.mget(redis_key_prefix+"bytes_in", redis_key_prefix+"bytes_out", redis_key_prefix+"known_connected")
        if bytes_in is not None and bytes_out is not None and known_connected:
            self.db.query("UPDATE vpn_per_device SET end_time_real=%s, bytes_in=%s, bytes_out=%s, known_connected=%s WHERE cert_name=%s AND end_time_real is NULL AND server_hostname=%s" % (self.escape(end_time_real), self.escape(bytes_in), self.escape(bytes_out), self.escape(known_connected), self.escape(cert_name), self.escape(self.server_hostname)))
            self.db.store_result()
            self.redis.delete(redis_key_prefix+"bytes_in", redis_key_prefix+"bytes_out", redis_key_prefix+"known_connected", redis_key_prefix+"last_update")
        else:
            self.db.query("UPDATE vpn_per_device SET end_time_real=%s WHERE cert_name=%s AND end_time_real is NULL AND server_hostname=%s" % (self.escape(end_time_real), self.escape(cert_name), self.escape(self.server_hostname)))
            self.db.store_result()
        statsd.gauge("vpn.traffic.in."+cert_name, 0)
        statsd.gauge("vpn.traffic.out."+cert_name, 0)

    @timing("vpn.update.session.update")
    def update_session(self, cert_name, bytes_in, bytes_out):
        now = datetime.datetime.now()
        redis_key_prefix = "openvpn-update-tmp-%s-%s-" % (self.server_hostname, cert_name)
        last_update = self.redis.get(redis_key_prefix+"last_update")
        statsd.gauge("vpn.traffic.in."+cert_name, bytes_in)
        statsd.gauge("vpn.traffic.out."+cert_name, bytes_out)
        if last_update:
            last_update = float(last_update)
        else:
            last_update = 0
        if random.random() < 0.18 or time.time() - last_update > 60 + random.random() * 20:
            statsd.incr("vpn.update.session.update")
            self.db.query("UPDATE vpn_per_device SET known_connected=%s, bytes_in=%s, bytes_out=%s WHERE server_hostname=%s AND cert_name=%s AND end_time_real is NULL" % (self.escape(now), self.escape(bytes_in), self.escape(bytes_out), self.escape(self.server_hostname), self.escape(cert_name)))
            self.db.store_result()
            self.redis.delete(redis_key_prefix+"bytes_in", redis_key_prefix+"bytes_out", redis_key_prefix+"known_connected")
            self.redis.set(redis_key_prefix+"last_update", time.time())
        else:
            statsd.incr("vpn.update.session.postpone_update")
            self.redis.mset({
             redis_key_prefix+"byte_in": bytes_in, 
             redis_key_prefix+"byte_out": bytes_out, 
             redis_key_prefix+"known_connected": now})


    def update(self, details):
        statsd.incr("vpn.update.update")
        cert_name = details["Common Name"]
        if cert_name == "UNDEF":
            return
        username = cert_name.split("-")[0]
        connection_start = details['Connected Since (time_t)']
        previous_connection_start = self.redis.get("openvpn-connection-start-%s-%s" % (self.server_hostname, cert_name))

        if len(details["Virtual Address"]) < 8:
            return
 
        if not self.redis.sismember("openvpn-connected-%s" % self.server_hostname, cert_name):
            # Not connected. Open a new session.
            self.open_session(username, cert_name, details["Virtual Address"], details['Real Address'], details['connected_since'], None, details['Bytes Sent'], details['Bytes Received'])
        else:
            # Already connected. Check connection timestamp.
            if str(connection_start) == previous_connection_start:
                # Update counters.
                self.update_session(cert_name, details['Bytes Sent'], details['Bytes Received'])
            else:
                # New connection.
                self.open_session(username, cert_name, details["Virtual Address"], details['Real Address'], details['connected_since'], None, details['Bytes Sent'], details['Bytes Received'])

        self.redis.set("openvpn-connection-start-%s-%s" % (self.server_hostname, cert_name), connection_start)
        self.redis.sadd("openvpn-connected-%s-tmp" % self.server_hostname, cert_name)

    @timing("vpn.update.finish")
    def finish(self):
        def disconnect_clients(certs):
            for cert_name in certs:
                self.close_session(cert_name, None)

        dc_key = "openvpn-connected-%s" % self.server_hostname
        dc_key_new = dc_key+"-tmp"
        if self.redis.exists(dc_key):
            # Old key exists
            if self.redis.exists(dc_key_new):
                # ... new key exists too. Diff and disconnect.
                disconnected_certs = self.redis.sdiff(dc_key, dc_key_new)
            else:
                # only old key exists - no entries available.
                disconnected_certs = self.redis.smembers(dc_key)
                # delete old key - not needed anymore.
                self.redis.delete(dc_key)
            disconnect_clients(disconnected_certs)

        if self.redis.exists(dc_key_new):
            # New key exists. Rename.
            self.redis.rename(dc_key_new, dc_key)

def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

@timing("vpn.update.main")
def application(environ, start_response):
    statsd.incr("vpn.update.main.counter")
    start_response("200 OK", [("Content-Type", "text/plain")])
    query_string = environ["QUERY_STRING"]
    query_string = query_string.split("&")
    hostname = False
    for item in query_string:
        item = item.split("=")
        if len(item) == 2:
            if item[0] == "server":
                if is_valid_hostname(item[1]):
                    hostname = item[1]
    if not hostname:
        return ["Invalid hostname"]

    vpn_update = VPNUpdate(hostname)
    vpn = OpenVPNStatusParser(environ["wsgi.input"])
    for cert_name in vpn.connected_clients:
        vpn_update.update(vpn.connected_clients[cert_name])
    vpn_update.finish()
    
    return [str(vpn.connected_clients)]
