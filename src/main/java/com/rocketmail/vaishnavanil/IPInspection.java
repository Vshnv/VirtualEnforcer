package com.rocketmail.vaishnavanil;

import org.apache.commons.lang3.StringUtils;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class IPInspection {
    IPProfile profile;


    public IPInspection(String IP){
        IPProfile profile;
        try{
        profile =(Enforcer.getDataAccessObject().queryForId(IP));
        }catch (Exception e){
            profile = new IPProfile();
            profile.ip= IP;
            profile.emails = new ArrayList<String>();
            profile.sessionClientMap = new HashMap<String, String>();
            try {
                Enforcer.getDataAccessObject().create(profile);
            } catch (SQLException e1) {
                e1.printStackTrace();
            }
        }
    }

    public boolean[] getResults(){
        return new boolean[]{perClientMultiSessTest(),performIdentifierTests(),performVPNPortScan()};
    }


    static final int DIFF_CLIENT_THRESHHOLD = 2;

    /**
     *
     * @return true, if pass ; false, if fail;
     */
    public boolean perClientMultiSessTest(){
        int i = 0;
        for(String client:profile.sessionClientMap.values()){
            for(String client2:profile.sessionClientMap.values()){
                if(client.equals(client2))i++;
                break;
            }
        }
        i /= 2;
        if(i>DIFF_CLIENT_THRESHHOLD)return false;
        return true;
    }

    /**
     *
     * @param port
     * @return true, if open ;     false , if closed;
     */

    private boolean testPort(int port){
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(profile.ip, port), 150);
            socket.close();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static int[] ports = {80,81,8080,443,1080,6588,3128};
    /**
     *
     * @return true, if pass ;     false , if fail;
     */
    public boolean performVPNPortScan(){
        for(int p:ports){
            if(!testPort(p))return false;
        }
        return true;
    }
    static final String[] trusted = {"gmail.com","hotmail.com","rocketmail.com","yahoo.com","msn.com"};
    static final int IP_EMAIL_THRESHHOLD = 15;
    static final int IP_DISTINCT_THRESHHOLD = 8;


    public boolean performIdentifierTests(){
        if(profile.emails.size() > IP_EMAIL_THRESHHOLD)return false;
        int distinctMails = 0;
        int illegitmate = 0;
        int index = 0;
        String[] mailStart = new String[profile.emails.size()];
        for(String email:profile.emails){
            String[] sep = email.split("@");
            if(!Arrays.stream(trusted).anyMatch(i -> {
                if(i.equals(sep[1]))
                return true;
            return false;})){
                illegitmate++;
            }
            mailStart[index++] = sep[1];
        }
        for(String s:mailStart){
            for(String s1:mailStart){
                if(s == s1)continue;
                if((double)StringUtils.getLevenshteinDistance(s,s1)/(double)(s.length()*s1.length()) > 75D){
                    distinctMails++;
                }
            }
        }
        distinctMails /= 2;
        if(distinctMails > IP_DISTINCT_THRESHHOLD)return false;
        if((double)illegitmate/(double)profile.emails.size() > 50)return false;
        return true;
    }
}
