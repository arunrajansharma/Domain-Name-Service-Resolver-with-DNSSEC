import org.xbill.DNS.*;
import java.io.*;
import java.util.*;
import java.net.*;


public class MyDigPerformance{
   static int index = 0;
   static String domainName ="";
   static long sTime = 0;
   static long eTime = 0;
	public static void main(String[] args) {
		
		int dType = Type.A;  // will be used to create a 'Record' for query
		int dClass = DClass.IN; // Internet class
		
		String fileNameServer = "RootServerList.txt";
		String fileNameWebsites = "Websites.txt";
		List<String> rootServerList = new ArrayList<String>();
		List<String> webSiteList = new ArrayList<String>();
		
		System.out.println("Loading necessary Files....");
		try{
		buildRootList(fileNameServer,rootServerList);
		}
		catch(FileNotFoundException ex){
			System.out.println("Unable to open the file, Please check");
			System.exit(0);
		}
		catch(IOException ex){
			System.out.println("Some exception happened, Printing the trace");
			ex.printStackTrace();
		}	
		
		System.out.println("Root List Loaded");
		System.out.println("Loading Top 25 Website List");
		try{
			buildWebsiteList(fileNameWebsites,webSiteList);
		}
		catch(FileNotFoundException ex){
			System.out.println("Unable to open the file, Please check");
			System.exit(0);
		}
		catch(IOException ex){
			System.out.println("Some exception happened, Printing the trace");
			ex.printStackTrace();
		}
		System.out.println("Website list loaded");
		
		for(String str: webSiteList){
			String[] D_T = str.split(" ");
			domainName = D_T[0];
			String typeGiven = D_T[1];
			//Input checks
			if(domainName == null || domainName.length()==0){
				System.out.println("Please provide (atleast try to) correct domain");
				System.exit(0);
			}
			switch(typeGiven){
			case "A":
				dType = Type.A;
				break;
			case "NS":
				dType = Type.NS;
				break;
			case "MX":
				dType = Type.MX;
				break;
			default:
				System.out.println("Provide valid Domain Type : 'A','NS','MX'");
				System.exit(0);
			}
		
			int i=0;
			domainName +=".";
			sTime = System.nanoTime();
			
			while(i<rootServerList.size()){
				String rootServer = rootServerList.get(i++);
			try{   
			        Resolver simpleResolver = new SimpleResolver(rootServer);
			        simpleResolver.setEDNS(0, 0, 0|1<<15, null);
					Name dName = Name.fromString(domainName);
					Record record = Record.newRecord(dName, dType, dClass);
					Message query = Message.newQuery(record); 
					Message response = simpleResolver.send(query);
					/* If we reach this point, it means we could find an entry in the 
					 * root server list, we would try to find the desired result by 
					 * calling a helper function, that can also throw an exception. The reason
					 * for that is the same as correspondence with root server : timeout or any
					 * other problem.
					 */
					 Message finalAnswer = helper(response,query);
					 if(finalAnswer == null)
						 continue;
					 Record[] rArray;
				     if(dType == Type.NS){
				    	  rArray = finalAnswer.getSectionArray(Section.AUTHORITY);
				    	  for(Record r: rArray){
				    		  //System.out.println(r.toString());
				    	  }
				     }
				     else{
				    	 rArray = finalAnswer.getSectionArray(Section.ANSWER);
				    	  for(Record r: rArray){
				    		 // System.out.println(r.toString());
				    	  }
				     }
				     eTime = System.nanoTime();
				    // System.out.println("Query Time  "+(eTime-sTime)/1000000+" msec");
				     System.out.println((eTime-sTime)/1000000);
					 break;
				} 
			catch(Exception ex){
				ex.printStackTrace();
				if(i==rootServerList.size()){
					System.out.println("Exhausted the complete Root Server list, Sorry");
					System.exit(0);
				}
				//System.out.println("Could not find at this root server :"+rootServer);
				
			  }
				
			}
		
		}
		
	}// main ends here
	
	static Message helper(Message response, Message query) throws IOException{
		while(true){
			Record[] rArray = response.getSectionArray(Section.AUTHORITY);
			if(rArray.length!=0){
				int count = 0;
				for(Record r: rArray){
					try{
						if(r.getType() == Type.SOA)
							return response;
						Resolver simpleResolver = new SimpleResolver(r.rdataToString());
						Message tempResponse = simpleResolver.send(query);
						response = tempResponse;
						if(response.getSectionArray(Section.ANSWER).length!=0){
							Record[] rAnsArray = response.getSectionArray(Section.ANSWER);
							for(Record rAns:rAnsArray){
								if(rAns.getType()==Type.CNAME){
									/* This is a special case, we can not resolve it here, have to to notify the API talking to root server
									 * also, domain name has to be changed, we need to look for CNAME now
									 * 
									 */
									domainName = rAns.rdataToString();
									return null;
								}
								else{
									return response;
								}
							}
						}
					}
					catch (Exception ex){
						if(++count==rArray.length)
							return null;
					}
				}
			}	
		}// while loop ends here		
	}
	
	
	/*Function to load the root server IP's from the text file. We only got 13 root servers
	 * @param fname: text file name
	 * @param rootList : container to be filled used in the main program
	 */
	static void buildRootList(String fname, List<String> rootList)throws FileNotFoundException, IOException{
		String line = null;
		FileReader fileReader = new FileReader(fname);
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		while((line=bufferedReader.readLine()) !=null){
			rootList.add(line);
		}	
		bufferedReader.close();
	}
	/*Function to load the top 25 websites from Alexa from the text file. 
	 * @param fname: text file name
	 * @param rootList : container to be filled used in the main program
	 */
	static void buildWebsiteList(String fname, List<String> rootList)throws FileNotFoundException, IOException{
		String line = null;
		FileReader fileReader = new FileReader(fname);
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		while((line=bufferedReader.readLine()) !=null){
			rootList.add(line);
		}	
		bufferedReader.close();
	}
	
		
	
}
