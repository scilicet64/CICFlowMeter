package cic.cs.unb.ca.jnetpcap;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.TimeZone;

public class DateFormatter {
	
	public static String parseDateFromLong(long time, String format,String timeZone){
		try{
			if (format == null){
				format = "dd/MM/yyyy hh:mm:ss";					
			}
			if (timeZone == null){
				timeZone = "CDT";
			}

			TimeZone tz = TimeZone.getTimeZone(timeZone);
			SimpleDateFormat simpleFormatter = new SimpleDateFormat(format);
			simpleFormatter.setTimeZone(tz);
			Date tempDate = new Date(time);
			return simpleFormatter.format(tempDate);
		}catch(Exception ex){
			System.out.println(ex.toString());
			return "dd/MM/yyyy hh:mm:ss";
		}		
	}

	public static String convertMilliseconds2String(long time, String format) {

        if (format == null){
            format = "dd/MM/yyyy hh:mm:ss";
        }

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
        LocalDateTime ldt = LocalDateTime.ofInstant(Instant.ofEpochMilli(time), ZoneId.systemDefault());
        return ldt.format(formatter);
	}

}
