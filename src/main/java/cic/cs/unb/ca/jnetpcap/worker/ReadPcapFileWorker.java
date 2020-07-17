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

    public ReadPcapFileWorker(File inputFile, String outPutDir, String labelDir) {
        super();
        pcapPath = inputFile;
        outPutDirectory = outPutDir;
        LabelDirectory = labelDir;
        chunks = new ArrayList<>();

        if(!outPutDirectory.endsWith(FILE_SEP)) {
            outPutDirectory = outPutDirectory + FILE_SEP;
        }

        if(!LabelDirectory.endsWith(FILE_SEP)) {
            LabelDirectory = LabelDirectory + FILE_SEP;
        }

        flowTimeout = 120000000L;
        activityTimeout = 5000000L;
    }

    public ReadPcapFileWorker(File inputFile, String outPutDir, String labelDir, long param1,long param2) {
        super();
        pcapPath = inputFile;
        outPutDirectory = outPutDir;
        LabelDirectory = labelDir;
        chunks = new ArrayList<>();

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

        File labelFileFullPath = new File(this.LabelDirectory+fileName.replace(".pcap","")+Utils.FLOW_SUFFIX);

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
                        //String firstColumn=values.get(0);
                        if (!values.get(0).equals("Flow ID")){
                            System.out.println("Warning!!!: Flow ID not found in label-file found(" +values.get(0)+")");
                        }
                        else {
                            idfoundInLabels = true;
                        }
                        if (!values.get(values.size()-1).replace(" ","").equals("Label")){
                            System.out.println("Warning!!!: Label not found in label-file found("+values.get(values.size()-1)+")");
                        }
                        firstline=false;
                    }
                    else {
                        String id="";
                        if (idfoundInLabels) {
                            id = values.get(0);
                        }
                        else {
                            //this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort  + "-" + this.dstPort  + "-" + this.protocol;
                            // fat warning.... timestamps do not match on ids2017 2018 datasets
                             id = values.get(0)+ "*" + values.get(1) + "*" + values.get(2);//Dst Port(0), Protocol(1), Timestamp(2)
                            }
                        //List<String> results = new ArrayList<String>();
                        String label = values.get(values.size() - 1);
                        String foundLabel = labels.get(id);
                        if (foundLabel!=null){
                            if (!label.equals(foundLabel)) {
                               System.out.println("Warning: label with id:" + id + " changed from:" + foundLabel+ " to:" + label);
                            }
                        }
                        labels.put(id, label);
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

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName));
        flowGen.addLabels(labels,idfoundInLabels);
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);
        publish(String.format("Working on... %s",inputFile));
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
        public void onFlowGenerated(BasicFlow flow) {
            firePropertyChange(PROPERTY_FLOW,fileName,flow);
        }
    }

}
