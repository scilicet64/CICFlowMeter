package cic.cs.unb.ca.jnetpcap;

import java.text.SimpleDateFormat;
import java.time.*;

import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.TimeZone;

public class DateFormatter {
	
	public static String parseDateFromLong(long time, String format,String timeZone){
		System.out.println("parseDateFromLong" );
		try{
			if (format == null){
				format = "dd/MM/yyyy hh:mm:ss a";
			}
			if (timeZone == null){
				timeZone = "CDT";
				System.out.println("Using Default Timezone:" + timeZone);
			}

			TimeZone tz = TimeZone.getTimeZone(timeZone);
			SimpleDateFormat simpleFormatter = new SimpleDateFormat(format);
			Date tempDate = new Date(time);
			System.out.println("no TZ" + simpleFormatter.format(tempDate));

			simpleFormatter.setTimeZone(tz);
			System.out.println("TZ" + simpleFormatter.format(tempDate));
			return simpleFormatter.format(tempDate);
		}catch(Exception ex){
			System.out.println(ex.toString());
			return "dd/MM/yyyy hh:mm:ss a";
		}		
	}

	public static String convertMilliseconds2String(long time, String format,String timeZone) {

        if (format == null){
            format = "dd/MM/yyyy hh:mm:ss a";
        }
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
		return Instant.ofEpochMilli(time).atZone(ZoneId.of(timeZone)).format(formatter);
	}

}
