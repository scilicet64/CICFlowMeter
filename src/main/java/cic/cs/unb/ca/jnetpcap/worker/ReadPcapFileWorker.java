package cic.cs.unb.ca.jnetpcap.worker;

import cic.cs.unb.ca.jnetpcap.*;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static cic.cs.unb.ca.jnetpcap.Utils.*;


public class ReadPcapFileWorker extends SwingWorker<List<String>,String> {

    public static final Logger logger = LoggerFactory.getLogger(ReadPcapFileWorker.class);
    public static final String PROPERTY_FILE_CNT = "file_count";
    public static final String PROPERTY_CUR_FILE = "file_current";
    public static final String PROPERTY_FLOW = "file_flow";
    private static final String DividingLine = "---------------------------------------------------------------------------------------------------------------";

    private long flowTimeout;
    private long activityTimeout;
    private int     totalFlows = 0;
    
    private File pcapPath;
    private String outPutDirectory;
    private String LabelDirectory;
    private List<String> chunks;
    private String timezone;

    public ReadPcapFileWorker(File inputFile, String outPutDir, String labelDir,String timeZone) {
        super();
        pcapPath = inputFile;
        outPutDirectory = outPutDir;
        LabelDirectory = labelDir;
        chunks = new ArrayList<>();
        this.timezone = timezone;

        if(!outPutDirectory.endsWith(FILE_SEP)) {
            outPutDirectory = outPutDirectory + FILE_SEP;
        }

        if(!LabelDirectory.endsWith(FILE_SEP)) {
            LabelDirectory = LabelDirectory + FILE_SEP;
        }

        flowTimeout = 120000000L;
        activityTimeout = 5000000L;
    }

    public ReadPcapFileWorker(File inputFile, String outPutDir, String labelDir, long param1,long param2,String timezone) {
        super();
        pcapPath = inputFile;
        outPutDirectory = outPutDir;
        LabelDirectory = labelDir;
        chunks = new ArrayList<>();
        this.timezone = timezone;

        if(!outPutDirectory.endsWith(FILE_SEP)) {
            outPutDirectory = outPutDirectory + FILE_SEP;
        }

        flowTimeout = param1;
        activityTimeout = param2;
    }

    @Override
    protected List<String> doInBackground() {

        if (pcapPath.isDirectory()) {
            readPcapDir(pcapPath,outPutDirectory);
        } else {

            if (!isPcapFile(pcapPath)) {
                publish("Please select pcap file!");
                publish("");
            } else {
                publish("CICFlowMeter received 1 pcap file");
                publish("");
                publish("");

                firePropertyChange(PROPERTY_CUR_FILE,"",pcapPath.getName());
                firePropertyChange(PROPERTY_FILE_CNT,1,1);//begin with 1
                readPcapFile(pcapPath.getPath(), outPutDirectory);
            }
        }
        /*chunks.clear();
        chunks.add("");
        chunks.add(DividingLine);
        chunks.add(String.format("TOTAL FLOWS GENERATED :%s", totalFlows));
        chunks.add(DividingLine);
        publish(chunks.toArray( new String[chunks.size()]));*/

        return chunks;
    }

    @Override
    protected void done() {
        super.done();
    }

    @Override
    protected void process(List<String> chunks) {
        super.process(chunks);
        firePropertyChange("progress","",chunks);
    }

    private void readPcapDir(File inputPath, String outPath) {
        if(inputPath==null||outPath==null) {
            return;
        }

        //File[] pcapFiles = inputPath.listFiles(file -> file.getName().toLowerCase().endsWith("pcap"));
        File[] pcapFiles = inputPath.listFiles(file -> isPcapFile(file));

        int file_cnt = pcapFiles.length;
        logger.debug("CICFlowMeter found :{} pcap files", file_cnt);
        publish(String.format("CICFlowMeter found :%s pcap files", file_cnt));
        publish("");
        publish("");

        for(int i=0;i<file_cnt;i++) {
            File file = pcapFiles[i];
            if (file.isDirectory()) {
                continue;
            }
            firePropertyChange(PROPERTY_CUR_FILE,"",file.getName());
            firePropertyChange(PROPERTY_FILE_CNT,file_cnt,i+1);//begin with 1
            readPcapFile(file.getPath(),outPath);
        }

    }

    private void readPcapFile(String inputFile, String outPath) {

        if(inputFile==null ||outPath==null ) {
            return;
        }
        Dictionary<String, String> labels= new Hashtable();;
        Path p = Paths.get(inputFile);
        String fileName = p.getFileName().toString();//FilenameUtils.getName(inputFile);


        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }

        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }

        if(!this.LabelDirectory.endsWith(FILE_SEP)) {
            this.LabelDirectory += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath+fileName+Utils.FLOW_SUFFIX);

        File labelFileFullPath = new File(this.LabelDirectory+fileName+Utils.FLOW_SUFFIX);

        if (saveFileFullPath.exists()) {
            if (!saveFileFullPath.delete()) {
                System.out.println("Saved file full path cannot be deleted");
            }
        }
        Boolean idfoundInLabels=false;
        if (!labelFileFullPath.exists()) {
                chunks.clear();
                chunks.add(String.format("Optional Label file not found: %s",labelFileFullPath.getAbsolutePath()));
                chunks.add(DividingLine);
                publish(chunks.toArray( new String[chunks.size()]));
        }else{

            try (Scanner scanner = new Scanner(labelFileFullPath);) {
                Boolean firstline= true;
                Integer indexoffset = 0; //used when index is found in csv
                Integer flowID_index= -1;
                Integer label_index= -1;
                Integer activity_index= -1;
                Integer stage_index= -1;
                Integer timestamp_index= -1;
                chunks.clear();
                chunks.add("Reading Label file...");
                chunks.add(DividingLine);
                publish(chunks.toArray( new String[chunks.size()]));
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    List<String> values = new ArrayList<String>();
                    try (Scanner rowScanner = new Scanner(line)) {
                        rowScanner.useDelimiter(",");
                        while (rowScanner.hasNext()) {
                            values.add(rowScanner.next());
                        }
                    }
                    if (firstline){
                        if (line.startsWith(",")) indexoffset=1;
                        long totalColumns = line.chars().filter(ch -> ch == ',').count();
                        //String firstColumn=values.get(0);
                        for(int i=0; i<values.size();i++){
                            String columnName = values.get(i).replace(" ","").toLowerCase();
                            if(columnName.equals("flowid")){
                                flowID_index=i;
                                idfoundInLabels=true;
                            }
                            if(columnName.equals("srcip")){
                                indexoffset=i;//used for creating Flowid when it is missing
                            }
                            if(columnName.equals("timestamp")){
                                timestamp_index=i; //todo: can be used to match label with timestamp
                                //using timestamp for labels will not work when this tool's timeout settings is different from the original labels
                            }
                            if(columnName.equals("label")){
                                label_index=i;
                            }
                            if(columnName.equals("activity")){
                                activity_index=i;
                            }
                            if(columnName.equals("stage")){
                                stage_index=i;
                                if(activity_index==-1){
                                    System.out.println("Warning!!!: column stage found, but no activity column, using stage as label");
                                }
                            }

                        }

                        if(!idfoundInLabels){
                            System.out.println("Warning!!!: Flow ID not found in label-file found(" +values.get(flowID_index)+")");
                        }

                        firstline=false;
                    }
                    else {
                        String id="";
                        String timestamp="";
                        if (idfoundInLabels) {
                            id = values.get(flowID_index);
                        }
                        else {
                            //this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort  + "-" + this.dstPort  + "-" + this.protocol;
                            // fat warning.... timestamps do not match on ids2017 2018 datasets
                             id = values.get(0+indexoffset)+ "*" + values.get(1+indexoffset) + "*" + values.get(2+indexoffset);//Dst Port(0), Protocol(1), Timestamp(2)
                            }
                        if(timestamp_index!=-1){
                            timestamp=values.get(timestamp_index);
                        }
                        //id=id+"_"+timestamp; //
                        //List<String> results = new ArrayList<String>();
                        if((label_index!=-1)||(activity_index!=-1) ||(stage_index!=-1)){
                            String label ="";
                            String benign_check = "";
                            if (label_index!=-1){
                                label = values.get(label_index);
                            }
                            else if ((activity_index!=-1)&&(stage_index!=-1)){
                                label = values.get(activity_index) + "," + values.get(stage_index);
                                benign_check = "benign,benign";
                            }else if (activity_index!=-1){
                                label = values.get(activity_index);
                                benign_check = "benign";
                            }else if (stage_index!=-1){
                                label = values.get(stage_index);
                                benign_check = "benign";
                            }

                            String foundLabel = labels.get(id);
                            if (foundLabel!=null){
                                if (!label.equals(foundLabel)) {
                                    System.out.println("Warning: label with id:" + id + " changed from:" + foundLabel+ " to:" + label);
                                    if (label.toLowerCase().replace(" ","").replace("normal","benign").equals(benign_check)){
                                        label = foundLabel;
                                    }
                                }
                            }
                            labels.put(id, label);
                    }
                    }
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            chunks.clear();
            chunks.add(String.format("Found label size: %s",labels.size()));
            chunks.add(DividingLine);
            publish(chunks.toArray( new String[chunks.size()]));
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout,timezone);
        flowGen.addFlowListener(new FlowListener(fileName));
        flowGen.addLabels(labels,idfoundInLabels);
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);
        publish(String.format("WorKing on... %s",inputFile));
        logger.debug("Working on... {}",inputFile);

        int nValid=0;
        int nTotal=0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        while(true) {
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if(basicPacket !=null){
                    flowGen.addPacket(basicPacket);
                    nValid++;
                }else{
                    nDiscarded++;
                }
            }catch(PcapClosedException e){
                break;
            }
        }
        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());

        long lines = countLines(saveFileFullPath.getPath());

        long end = System.currentTimeMillis();

        chunks.clear();
        chunks.add(String.format("Done! Total %d flows",lines-1));
        chunks.add(String.format("Packets stats: Total=%d,Valid=%d,Discarded=%d",nTotal,nValid,nDiscarded));
        chunks.add(DividingLine);
        publish(chunks.toArray( new String[chunks.size()]));

        /*chunks.add(String.format("\t Total packets: %d",nTotal));
        chunks.add(String.format("\t Valid packets: %d",nValid));
        chunks.add(String.format("\t Ignored packets:%d %d ", nDiscarded,(nTotal-nValid)));
        chunks.add(String.format("PCAP duration %d seconds",((packetReader.getLastPacket()- packetReader.getFirstPacket())/1000)));
        chunks.add(DividingLine);
        int singleTotal = flowGen.dumpLabeledFlowBasedFeatures(outPath, fullname+ FlowMgr.FLOW_SUFFIX, FlowFeature.getHeader());
        chunks.add(String.format("Number of Flows: %d",singleTotal));
        chunks.add("");
        publish(chunks.toArray( new String[chunks.size()]));
        totalFlows += singleTotal;

        logger.debug("{} is done,Total {}",inputFile,singleTotal);*/
    }


    class FlowListener implements FlowGenListener {

        private String fileName;

        FlowListener(String fileName) {
            this.fileName = fileName;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow,String label) {
            firePropertyChange(PROPERTY_FLOW,fileName,flow);
        }
    }

}
