package cic.cs.unb.ca.jnetpcap;


import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public enum FlowFeature {

    fid("Flow ID","FID",false),					//1 this index is for feature not for ordinal
    src_ip("Src IP","SIP",false),				//2
    src_port("Src Port","SPT"),					//3
    dst_ip("Dst IP","DIP",false),				//4
    dst_pot("Dst Port","DPT"),					//5
    prot("Protocol","PROT"),					//6
    tstp("Timestamp","TSTP",false),				//7
    fl_dur("Flow Duration","DUR"),				//8
    tot_fw_pkt("Total Fwd Packet","TFwP"),			//9
    tot_bw_pkt("Total Bwd packets","TBwP"),			//10
    tot_l_fw_pkt("Total Length of Fwd Packet","TLFwP"),		//11
    tot_l_bw_pkt("Total Length of Bwd Packet","TLBwP"),		//12
    fw_pkt_l_max("Fwd Packet Length Max","FwPLMA"),		//13
    fw_pkt_l_min("Fwd Packet Length Min","FwPLMI"),		//14
    fw_pkt_l_avg("Fwd Packet Length Mean","FwPLAG"),		//15
    fw_pkt_l_std("Fwd Packet Length Std","FwPLSD"),		//16
    bw_pkt_l_max("Bwd Packet Length Max","BwPLMA"),		//17
    bw_pkt_l_min("Bwd Packet Length Min","BwPLMI"),		//18
    bw_pkt_l_avg("Bwd Packet Length Mean","BwPLAG"),		//19
    bw_pkt_l_std("Bwd Packet Length Std","BwPLSD"),		//20
    fl_byt_s("Flow Bytes/s","FB/s"),				//21
    fl_pkt_s("Flow Packets/s","FP/s"),				//22
    fl_iat_avg("Flow IAT Mean","FLIATAG"),			//23
    fl_iat_std("Flow IAT Std","FLIATSD"),			//24
    fl_iat_max("Flow IAT Max","FLIATMA"),			//25
    fl_iat_min("Flow IAT Min","FLIATMI"),			//26
    fw_iat_tot("Fwd IAT Total","FwIATTO"),			//27
    fw_iat_avg("Fwd IAT Mean","FwIATAG"),			//28
    fw_iat_std("Fwd IAT Std","FwIATSD"),			//29
    fw_iat_max("Fwd IAT Max","FwIATMA"),			//30
    fw_iat_min("Fwd IAT Min","FwIATMI"),			//31
    bw_iat_tot("Bwd IAT Total","BwIATTO"),			//32
    bw_iat_avg("Bwd IAT Mean","BwIATAG"),			//33
    bw_iat_std("Bwd IAT Std","BwIATSD"),			//34
    bw_iat_max("Bwd IAT Max","BwIATMA"),			//35
    bw_iat_min("Bwd IAT Min","BwIATMI"),			//36
    fw_psh_flag("Fwd PSH Flags","FwPSH"),			//37
    bw_psh_flag("Bwd PSH Flags","BwPSH"),			//38
    fw_urg_flag("Fwd URG Flags","FwURG"),			//39
    bw_urg_flag("Bwd URG Flags","BwURG"),			//40
    fw_hdr_len("Fwd Header Length","FwHL"),			//41
    bw_hdr_len("Bwd Header Length","BwHL"),			//42
    fw_pkt_s("Fwd Packets/s","FwP/s"),				//43
    bw_pkt_s("Bwd Packets/s","Bwp/s"),				//44
    pkt_len_min("Packet Length Min","PLMI"),			//45
    pkt_len_max("Packet Length Max","PLMA"),			//46
    pkt_len_avg("Packet Length Mean","PLAG"),			//47
    pkt_len_std("Packet Length Std","PLSD"),			//48
    pkt_len_var("Packet Length Variance","PLVA"),		//49
    fin_cnt("FIN Flag Count","FINCT"),				//50
    syn_cnt("SYN Flag Count","SYNCT"),				//51
    rst_cnt("RST Flag Count","RSTCT"),				//52
    pst_cnt("PSH Flag Count","PSHCT"),				//53
    ack_cnt("ACK Flag Count","ACKCT"),				//54
    urg_cnt("URG Flag Count","URGCT"),				//55
    CWR_cnt("CWR Flag Count","CWRCT"),				//56
    ece_cnt("ECE Flag Count","ECECT"),				//57
    down_up_ratio("Down/Up Ratio","D/URO"),			//58
    pkt_size_avg("Average Packet Size","PSAG"),			//59
    fw_seg_avg("Fwd Segment Size Avg","FwSgAG"),		//60
    bw_seg_avg("Bwd Segment Size Avg","BwSgAG"),		//61
    fw_byt_blk_avg("Fwd Bytes/Bulk Avg","FwB/BAG"),		//63   62 is duplicated with 41,so has been deleted
    fw_pkt_blk_avg("Fwd Packet/Bulk Avg","FwP/BAG"),		//64
    fw_blk_rate_avg("Fwd Bulk Rate Avg","FwBRAG"),		//65
    bw_byt_blk_avg("Bwd Bytes/Bulk Avg","BwB/BAG"),		//66
    bw_pkt_blk_avg("Bwd Packet/Bulk Avg","BwP/BAG"),		//67
    bw_blk_rate_avg("Bwd Bulk Rate Avg","BwBRAG"),		//68
    subfl_fw_pkt("Subflow Fwd Packets","SFFwP"),		//69
    subfl_fw_byt("Subflow Fwd Bytes","SFFwB"),			//70
    subfl_bw_pkt("Subflow Bwd Packets","SFBwP"),		//71
    subfl_bw_byt("Subflow Bwd Bytes","SFBwB"),			//72
    fw_win_byt("FWD Init Win Bytes","FwWB"),			//73
    bw_win_byt("Bwd Init Win Bytes","BwWB"),			//74
    Fw_act_pkt("Fwd Act Data Pkts","FwAP"),			//75
    fw_seg_min("Fwd Seg Size Min","FwSgMI"),			//76
    atv_avg("Active Mean","AcAG"),				//77
    atv_std("Active Std","AcSD"),				//78
    atv_max("Active Max","AcMA"),				//79
    atv_min("Active Min","AcMI"),				//80
    idl_avg("Idle Mean","IlAG"),				//81
    idl_std("Idle Std","IlSD"),					//82
    idl_max("Idle Max","IlMA"),					//83
    idl_min("Idle Min","IlMI"),					//84
    payload0("Payload0","p0"),				//85
    payload1("Payload1","p1"),				//86
    payload2("Payload2","p2"),				//87
    payload3("Payload3","p3"),				//88
    payload4("Payload4","p4"),				//89
    payload5("Payload5","p5"),				//90
    payload6("Payload6","p6"),				//91
    payload7("Payload7","p7"),				//92
    payload8("Payload8","p8"),				//93
    payload9("Payload9","p9"),				//94
    payload10("Payload10","p10"),				//95
    payload11("Payload11","p11"),				//96
    payload12("Payload12","p12"),				//97
    payload13("Payload13","p13"),				//98
    payload14("Payload14","p14"),				//99
    payload15("Payload15","p15"),				//100
    payload16("Payload16","p16"),				//101
    payload17("Payload17","p17"),				//102
    payload18("Payload18","p18"),				//103
    payload19("Payload19","p19"),				//104
    payload20("Payload20","p20"),				//105
    payload21("Payload21","p21"),				//106
    payload22("Payload22","p22"),				//107
    payload23("Payload23","p23"),				//108
    payload24("Payload24","p24"),				//109
    payload25("Payload25","p25"),				//110
    payload26("Payload26","p26"),				//111
    payload27("Payload27","p27"),				//112
    payload28("Payload28","p28"),				//113
    payload29("Payload29","p29"),				//114
    payload30("Payload30","p30"),				//115
    payload31("Payload31","p31"),				//116
    payload32("Payload32","p32"),				//117
    payload33("Payload33","p33"),				//118
    payload34("Payload34","p34"),				//119
    payload35("Payload35","p35"),				//120
    payload36("Payload36","p36"),				//121
    payload37("Payload37","p37"),				//122
    payload38("Payload38","p38"),				//123
    payload39("Payload39","p39"),				//124
    payload40("Payload40","p40"),				//125
    payload41("Payload41","p41"),				//126
    payload42("Payload42","p42"),				//127
    payload43("Payload43","p43"),				//128
    payload44("Payload44","p44"),				//129
    payload45("Payload45","p45"),				//130
    payload46("Payload46","p46"),				//131
    payload47("Payload47","p47"),				//132
    payload48("Payload48","p48"),				//133
    payload49("Payload49","p49"),				//134
    payload50("Payload50","p50"),				//135
    payload51("Payload51","p51"),				//136
    payload52("Payload52","p52"),				//137
    payload53("Payload53","p53"),				//138
    payload54("Payload54","p54"),				//139
    payload55("Payload55","p55"),				//140
    payload56("Payload56","p56"),				//141
    payload57("Payload57","p57"),				//142
    payload58("Payload58","p58"),				//143
    payload59("Payload59","p59"),				//144
    payload60("Payload60","p60"),				//145
    payload61("Payload61","p61"),				//146
    payload62("Payload62","p62"),				//147
    payload63("Payload63","p63"),				//148
    payload64("Payload64","p64"),				//149
    payload65("Payload65","p65"),				//150
    payload66("Payload66","p66"),				//151
    payload67("Payload67","p67"),				//152
    payload68("Payload68","p68"),				//153
    payload69("Payload69","p69"),				//154
    payload70("Payload70","p70"),				//155
    payload71("Payload71","p71"),				//156
    payload72("Payload72","p72"),				//157
    payload73("Payload73","p73"),				//158
    payload74("Payload74","p74"),				//159
    payload75("Payload75","p75"),				//160
    payload76("Payload76","p76"),				//161
    payload77("Payload77","p77"),				//162
    payload78("Payload78","p78"),				//163
    payload79("Payload79","p79"),				//164
    payload80("Payload80","p80"),				//165
    payload81("Payload81","p81"),				//166
    payload82("Payload82","p82"),				//167
    payload83("Payload83","p83"),				//168
    payload84("Payload84","p84"),				//169
    payload85("Payload85","p85"),				//170
    payload86("Payload86","p86"),				//171
    payload87("Payload87","p87"),				//172
    payload88("Payload88","p88"),				//173
    payload89("Payload89","p89"),				//174
    payload90("Payload90","p90"),				//175
    payload91("Payload91","p91"),				//176
    payload92("Payload92","p92"),				//177
    payload93("Payload93","p93"),				//178
    payload94("Payload94","p94"),				//179
    payload95("Payload95","p95"),				//180
    payload96("Payload96","p96"),				//181
    payload97("Payload97","p97"),				//182
    payload98("Payload98","p98"),				//183
    payload99("Payload99","p99"),				//184
    payload100("Payload100","p100"),				//185
    payload101("Payload101","p101"),				//186
    payload102("Payload102","p102"),				//187
    payload103("Payload103","p103"),				//188
    payload104("Payload104","p104"),				//189
    payload105("Payload105","p105"),				//190
    payload106("Payload106","p106"),				//191
    payload107("Payload107","p107"),				//192
    payload108("Payload108","p108"),				//193
    payload109("Payload109","p109"),				//194
    payload110("Payload110","p110"),				//195
    payload111("Payload111","p111"),				//196
    payload112("Payload112","p112"),				//197
    payload113("Payload113","p113"),				//198
    payload114("Payload114","p114"),				//199
    payload115("Payload115","p115"),				//200
    payload116("Payload116","p116"),				//201
    payload117("Payload117","p117"),				//202
    payload118("Payload118","p118"),				//203
    payload119("Payload119","p119"),				//204
    payload120("Payload120","p120"),				//205
    payload121("Payload121","p121"),				//206
    payload122("Payload122","p122"),				//207
    payload123("Payload123","p123"),				//208
    payload124("Payload124","p124"),				//209
    payload125("Payload125","p125"),				//210
    payload126("Payload126","p126"),				//211
    payload127("Payload127","p127"),				//212
    payload128("Payload128","p128"),				//213
    payload129("Payload129","p129"),				//214
    payload130("Payload130","p130"),				//215
    payload131("Payload131","p131"),				//216
    payload132("Payload132","p132"),				//217
    payload133("Payload133","p133"),				//218
    payload134("Payload134","p134"),				//219
    payload135("Payload135","p135"),				//220
    payload136("Payload136","p136"),				//221
    payload137("Payload137","p137"),				//222
    payload138("Payload138","p138"),				//223
    payload139("Payload139","p139"),				//224
    payload140("Payload140","p140"),				//225
    payload141("Payload141","p141"),				//226
    payload142("Payload142","p142"),				//227
    payload143("Payload143","p143"),				//228
    payload144("Payload144","p144"),				//229
    payload145("Payload145","p145"),				//230
    payload146("Payload146","p146"),				//231
    payload147("Payload147","p147"),				//232
    payload148("Payload148","p148"),				//233
    payload149("Payload149","p149"),				//234
    payload150("Payload150","p150"),				//235
    payload151("Payload151","p151"),				//236
    payload152("Payload152","p152"),				//237
    payload153("Payload153","p153"),				//238
    payload154("Payload154","p154"),				//239
    payload155("Payload155","p155"),				//240
    payload156("Payload156","p156"),				//241
    payload157("Payload157","p157"),				//242
    payload158("Payload158","p158"),				//243
    payload159("Payload159","p159"),				//244
    payload160("Payload160","p160"),				//245
    payload161("Payload161","p161"),				//246
    payload162("Payload162","p162"),				//247
    payload163("Payload163","p163"),				//248
    payload164("Payload164","p164"),				//249
    payload165("Payload165","p165"),				//250
    payload166("Payload166","p166"),				//251
    payload167("Payload167","p167"),				//252
    payload168("Payload168","p168"),				//253
    payload169("Payload169","p169"),				//254
    payload170("Payload170","p170"),				//255
    payload171("Payload171","p171"),				//256
    payload172("Payload172","p172"),				//257
    payload173("Payload173","p173"),				//258
    payload174("Payload174","p174"),				//259
    payload175("Payload175","p175"),				//260
    payload176("Payload176","p176"),				//261
    payload177("Payload177","p177"),				//262
    payload178("Payload178","p178"),				//263
    payload179("Payload179","p179"),				//264
    payload180("Payload180","p180"),				//265
    payload181("Payload181","p181"),				//266
    payload182("Payload182","p182"),				//267
    payload183("Payload183","p183"),				//268
    payload184("Payload184","p184"),				//269
    payload185("Payload185","p185"),				//270
    payload186("Payload186","p186"),				//271
    payload187("Payload187","p187"),				//272
    payload188("Payload188","p188"),				//273
    payload189("Payload189","p189"),				//274
    payload190("Payload190","p190"),				//275
    payload191("Payload191","p191"),				//276
    payload192("Payload192","p192"),				//277
    payload193("Payload193","p193"),				//278
    payload194("Payload194","p194"),				//279
    payload195("Payload195","p195"),				//280
    payload196("Payload196","p196"),				//281
    payload197("Payload197","p197"),				//282
    payload198("Payload198","p198"),				//283
    payload199("Payload199","p199"),				//284
    payload200("Payload200","p200"),				//285
    payload201("Payload201","p201"),				//286
    payload202("Payload202","p202"),				//287
    payload203("Payload203","p203"),				//288
    payload204("Payload204","p204"),				//289
    payload205("Payload205","p205"),				//290
    payload206("Payload206","p206"),				//291
    payload207("Payload207","p207"),				//292
    payload208("Payload208","p208"),				//293
    payload209("Payload209","p209"),				//294
    payload210("Payload210","p210"),				//295
    payload211("Payload211","p211"),				//296
    payload212("Payload212","p212"),				//297
    payload213("Payload213","p213"),				//298
    payload214("Payload214","p214"),				//299
    payload215("Payload215","p215"),				//300
    payload216("Payload216","p216"),				//301
    payload217("Payload217","p217"),				//302
    payload218("Payload218","p218"),				//303
    payload219("Payload219","p219"),				//304
    payload220("Payload220","p220"),				//305
    payload221("Payload221","p221"),				//306
    payload222("Payload222","p222"),				//307
    payload223("Payload223","p223"),				//308
    payload224("Payload224","p224"),				//309
    payload225("Payload225","p225"),				//310
    payload226("Payload226","p226"),				//311
    payload227("Payload227","p227"),				//312
    payload228("Payload228","p228"),				//313
    payload229("Payload229","p229"),				//314
    payload230("Payload230","p230"),				//315
    payload231("Payload231","p231"),				//316
    payload232("Payload232","p232"),				//317
    payload233("Payload233","p233"),				//318
    payload234("Payload234","p234"),				//319
    payload235("Payload235","p235"),				//320
    payload236("Payload236","p236"),				//321
    payload237("Payload237","p237"),				//322
    payload238("Payload238","p238"),				//323
    payload239("Payload239","p239"),				//324
    payload240("Payload240","p240"),				//325
    payload241("Payload241","p241"),				//326
    payload242("Payload242","p242"),				//327
    payload243("Payload243","p243"),				//328
    payload244("Payload244","p244"),				//329
    payload245("Payload245","p245"),				//330
    payload246("Payload246","p246"),				//331
    payload247("Payload247","p247"),				//332
    payload248("Payload248","p248"),				//333
    payload249("Payload249","p249"),				//334
    payload250("Payload250","p250"),				//335
    payload251("Payload251","p251"),				//336
    payload252("Payload252","p252"),				//337
    payload253("Payload253","p253"),				//338
    payload254("Payload254","p254"),				//339
    payload255("Payload255","p255"),				//340
    fwdpayload("PayloadSent","fwdpayload"),		//341
    bwdpayload("PayloadReceived","bwdpayload"),//342
    Activity("Activity","Act",new String[]{"NeedManualLabel"}),	//343
    Stage("Stage","Stg",new String[]{"NeedManualLabel"});	//344


	protected static final Logger logger = LoggerFactory.getLogger(FlowFeature.class);
	private static String HEADER;
	private String name;
	private String abbr;
	private boolean isNumeric;
	private String[] values;

    FlowFeature(String name,String abbr,boolean numeric) {
        this.name = name;
        this.abbr = abbr;
        isNumeric = numeric;
    }

	FlowFeature(String name, String abbr) {
        this.name = name;
        this.abbr = abbr;
        isNumeric = true;

    }

	FlowFeature(String name,String abbr,String[] values) {
		this.name = name;
        this.abbr = abbr;
        this.values = values;
        isNumeric = false;
    }

	public String getName() {
		return name;
	}

    public String getAbbr() {
        return abbr;
    }

    public boolean isNumeric(){
        return isNumeric;
    }

	public static FlowFeature getByName(String name) {
		for(FlowFeature feature: FlowFeature.values()) {
			if(feature.getName().equals(name)) {
				return feature;
			}
		}
		return null;
	}
	
	public static String getHeader() {
		
		if(HEADER ==null|| HEADER.length()==0) {
			StringBuilder header = new StringBuilder();
			
			for(FlowFeature feature: FlowFeature.values()) {
				header.append(feature.getName()).append(",");
			}
			header.deleteCharAt(header.length()-1);
			HEADER = header.toString();
		}
		return HEADER;
	}

	public static List<FlowFeature> getFeatureList() {
        List<FlowFeature> features = new ArrayList<>();
        features.add(prot);
        for(int i = fl_dur.ordinal(); i<= idl_min.ordinal(); i++) {
            features.add(FlowFeature.values()[i]);
        }
        return features;
    }

	public static List<FlowFeature> getLengthFeature(){
		List<FlowFeature> features = new ArrayList<>();
		features.add(tot_l_fw_pkt);
		features.add(tot_l_bw_pkt);
		features.add(fl_byt_s);
		features.add(fl_pkt_s);
		features.add(fw_hdr_len);
		features.add(bw_hdr_len);
		features.add(fw_pkt_s);
		features.add(bw_pkt_s);
		features.add(pkt_size_avg);
		features.add(fw_seg_avg);
		features.add(bw_seg_avg);
		return features;
	}


    public static String featureValue2String(FlowFeature feature, String value) {
        String ret = value;

        switch (feature) {
            case prot:
                try {
                    int number  = NumberUtils.createNumber(value).intValue();
                    if (number == 6) {
                        ret = "TCP";

                    } else if (number == 17) {
                        ret = "UDP";

                    } else {
                        ret = "Others";
                    }
                } catch (NumberFormatException e) {
                    logger.info("NumberFormatException {} value is {}",e.getMessage(),value);
                    ret = "Others";
                }
            break;
        }

        return ret;
    }

	@Override
	public String toString() {
		return name;
	}
	
}
