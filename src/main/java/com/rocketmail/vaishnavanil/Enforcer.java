package com.rocketmail.vaishnavanil;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import spark.Request;
import spark.Response;
import spark.Route;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;

import static spark.Spark.get;
import static spark.Spark.post;

public class Enforcer {
    static Dao<IPProfile,String> ippDao;
    public static void main(String[] args) throws SQLException {
        String databaseUrl = "jdbc:mysql://localhost/spark";

        ConnectionSource connectionSource = new JdbcConnectionSource(databaseUrl);
        ((JdbcConnectionSource)connectionSource).setUsername("spark");
        ((JdbcConnectionSource)connectionSource).setPassword("spark");
        TableUtils.createTableIfNotExists(connectionSource, IPProfile.class);
        ippDao = DaoManager.createDao(connectionSource, IPProfile.class);

        /**
         * End session event for an IP
         */
        get(new Route("/enforcer/session/stop") {
            @Override
            public Object handle(Request request, Response response) {
                String ip = request.queryParams("ip");
                String client = request.queryParams("clientid");
                String session = request.queryParams("session");
                try {
                    response.status(200);
                    IPProfile profile = getDataAccessObject().queryForId(ip);
                    if(profile == null){
                        return "ERROR:IP not registered";
                    }
                    return profile.endSession(client,session);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                return "FAIL:internal error";
            }
        });
        /**
         * Start session for an IP
         */
        get(new Route("/enforcer/session/start") {

            @Override
            public Object handle(Request request, Response response) {
                String ip = request.queryParams("ip");
                String client = request.queryParams("clientid");

                try {
                    response.status(200);
                    IPProfile profile = getDataAccessObject().queryForId(ip);
                    if(profile == null){
                        profile = new IPProfile();
                        profile.ip = ip;
                        profile.sessionClientMap = new HashMap<>();
                        profile.sessionClientMap.put("test","test");
                        profile.emails = new ArrayList<>();
                        profile.emails.add("test");

                        getDataAccessObject().create(profile);
                    }
                    return profile.createNewSession(client);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                return "ERROR";
            }
        });

    }

    public static Dao<IPProfile,String> getDataAccessObject(){
        return ippDao;
    }
}
