package com.rocketmail.vaishnavanil;

import com.j256.ormlite.field.DataType;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

import java.sql.SQLException;
import java.util.*;


@DatabaseTable(tableName = "EnforcerIPProfiles")
public class IPProfile {
    @DatabaseField(id = true,dataType = DataType.STRING)
    String ip;
    @DatabaseField(dataType= DataType.SERIALIZABLE)
    ArrayList<String> emails;

    @DatabaseField(dataType=DataType.SERIALIZABLE)
    HashMap<String,String> sessionClientMap;

    public IPProfile(){}


    public String createNewSession(String ClientID){
        String SSID = UUID.randomUUID().toString();
        sessionClientMap.put(SSID,ClientID);
        try {
            Enforcer.getDataAccessObject().update(this);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return SSID;
    }

    public String endSession(String ClientID,String session){
        if(!sessionClientMap.containsKey(session))return "FAIL:session invalid";

        if(sessionClientMap.get(session).equals(ClientID)){
            sessionClientMap.remove(session);
            try {
                Enforcer.getDataAccessObject().update(this);
            } catch (SQLException e) {
                e.printStackTrace();
            }
            return "SUCCESS";
        }


        return "FAIL:session invalid";
    }
}
