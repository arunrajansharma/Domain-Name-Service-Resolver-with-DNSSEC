import org.xbill.DNS.*;
import java.io.*;
import java.security.PublicKey;
import java.io.*;
import java.util.*;

import javax.swing.plaf.basic.BasicInternalFrameTitlePane.SystemMenuBar;

import java.net.*;


public class MyDig{
   static int index = 0;
   static String domainName ="";
   static  String[] domainParts;
   static int domainIndex;
   static DSRecord prevDS;
   static String prevDname="";
   
   
	public static void main(String[] args) {
		
		int dType = Type.A;  // will be used to create a 'Record' for query
		int dClass = DClass.IN; // Internet class
		
		String fileName = "RootServerList.txt";
		List<String> rootServerList = new ArrayList<String>();
		
		System.out.println("Loading necessary Files....");
		try{
		buildRootList(fileName,rootServerList);
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
		
		System.out.println("Enter the domain Name");
		Scanner sc = new Scanner(System.in);
		domainName = sc.next();               // First time we take from user	
		//Input checks
		if(domainName == null || domainName.length()==0){
			System.out.println("Please provide (atleast try to) correct domain");
			System.exit(0);
		}
		
		domainParts = domainName.split("\\.");
		for(String str: domainParts)
				System.out.println(str);
		
		domainIndex = domainParts.length-1;
		
		
		sc.close();
		int i=0;
		while(i<rootServerList.size()){
			String rootServer = rootServerList.get(i++);
		try{   
		        Resolver simpleResolver = new SimpleResolver(rootServer);
		        simpleResolver.setEDNS(0, 0, Flags.DO, null);
		        String currDname = domainParts[domainIndex]+"."+prevDname;
				Name dName = Name.fromString(currDname); 
				// decrement the domainIndex after each step of DNSSEC verification
				
				Record record = Record.newRecord(dName, Type.DNSKEY, dClass);  // we would keep this Type always here
			    Message query = Message.newQuery(record); 
				Message response = simpleResolver.send(query);
				
				//System.out.println(response.toString());
				
			   // getting the DS from root's reply
				Record[] xyz =response.getSectionArray(Section.AUTHORITY);
				for(Record r: xyz){
					if(r.getType()==Type.DS){
						 prevDS = (DSRecord) r;
					}
				}
				
			
				
						/* If we reach this point, it means we could find an entry in the 
				 * root server list, we would try to find the desired result by 
				 * calling a helper function, that can also throw an exception. The reason
				 * for that is the same as correspondence with root server : timeout or any
				 * other problem.
				 */
				
				/*
				 * helper(Message response) can return three values 
				 *  0 : dnssec failed  --> don't proceed
				 *  1 : not enabled  ---> proceed 
				 *  2 : enabled and all Good  --> ofcourse, proceed
				 *  -1 : domain not correct
				 */
				 int finalAnswer = helper(response);
				 
				 System.out.println(finalAnswer);
				 
				 if(finalAnswer == 0){
					 System.out.println("DNSSEC failed, not proceeding");
					 System.exit(0);
				 }
				 if( finalAnswer == 1|| finalAnswer==2){
					    System.out.println(domainName);
					    dName = Name.fromString(domainName+".");
					    record = Record.newRecord(dName, Type.A, dClass);  //We would query for ip now
					     query = Message.newQuery(record); 
						 response = simpleResolver.send(query);
						 response = digHelper(response,query);
						 if(response==null)
							 	continue;
						 if(response !=null){
							 //System.out.println(response.toString());
							 Record[] rArray = response.getSectionArray(Section.ANSWER);
					    	  for(Record r: rArray){
					    		  System.out.println(r.toString());
					    	  }
						 } 
						// System.out.println(response.toString());
				 }
				
				 if(finalAnswer ==-1)
					 continue;
			     
				break;
			} 
		catch(Exception ex){
			ex.printStackTrace();
			if(i==rootServerList.size()){
				System.out.println("Exhausted the complete Root Server list, Sorry");
				System.exit(0);
			}
			System.out.println("Could not find at this root server :"+rootServer);
			
		  }
			
		}
		
	}// main ends here
	
	static int helper(Message response) throws IOException{
           
			Record[] rArray = response.getSectionArray(Section.AUTHORITY);
			if(rArray.length!=0){
				int count = 0;
				for(Record r: rArray){
					try{
 	                    Resolver simpleResolver = new SimpleResolver(r.rdataToString());
						simpleResolver.setEDNS(0, 0, Flags.DO, null);
						
						//First get DNSKEY 
						String currDname = domainParts[domainIndex]+"."+prevDname;
						//System.out.println(currDname);
						Name dName = Name.fromString(currDname); 
						
						Record record = Record.newRecord(dName, Type.DNSKEY, DClass.IN);
					    Message query = Message.newQuery(record); 
						
						Message tldResponse = simpleResolver.send(query);
						//System.out.println(tldResponse.toString());
						
						// Now we need to extract DNSKEY and RRSIG from tldResponse 
						
						Record[] ansArr = tldResponse.getSectionArray(Section.ANSWER);
						DNSKEYRecord dnsKey =null;
						RRSIGRecord  rrSig = null;
						for(Record r1: ansArr){
							if(r1.getType()==Type.DNSKEY){
								DNSKEYRecord d1  =  (DNSKEYRecord)r1;
								if(d1.getFlags()==257)
									dnsKey = d1;
							}
							if(r1.getType()==Type.RRSIG){
								rrSig = (RRSIGRecord)r1;
							}
						}
						
						// This is the part where we check to a certain level if a domain "abc.xyz" supports DNSSEC or not"
						
						if(domainParts.length-domainIndex==2 && rrSig==null){
							return 1;
						}
						
						// and do 2 things
						/* 1. makeDS and compare with response'DS
						 * 2. verify(DNSKEY, RRSIG, RRSet)
						 * 
						 */
					
						
						// Making DS Object 
						//DSRecord(Name name, int dclass, long ttl, int digestid, DNSKEYRecord key)
						DSRecord dsNew = new DSRecord(dName,DClass.IN, prevDS.getTTL(), prevDS.getDigestID(), dnsKey);
						
						// Compare newly created DS object dsNew with prevDS
						if(dsNew.equals(prevDS)){
							System.out.println("DS for "+dName.toString()+" Verified");
						}
						else{
							System.out.println("DS matching failed,"+dName.toString()+" returning");
							return 0;
						}
						
					    // Now verify the DNSKEY 
						//verify(RRset rrset, RRSIGRecord rrsig, DNSKEYRecord key) throws DNSSECException
						
					     RRset[] rrsetArr = tldResponse.getSectionRRsets(Section.ANSWER);
					     /*
					      * 
					      * Here, I have run into strange problem, NS has two RRSIG, probably one for ZSK and KSK;
					      * 
					      * 
					      */
					     
					     
					     // trying to verify with either of the RRSIG
					     for(Record r1: ansArr){
								if(r1.getType()==Type.RRSIG){
									rrSig = (RRSIGRecord)r1;
									 try{
										  DNSSEC.verify(rrsetArr[0], rrSig, dnsKey);
										  break;
									     }
									  catch (DNSSEC.DNSSECException ex){
									    	 //System.out.println("hoho " + rrSig.toString());
									    	 rrSig = null;
									     }
								}
							}
					     
					     if(rrSig==null)
					    	 	return 0;
						  
						 System.out.println("DNSKEY for "+"\""+dName.toString()+"\""+" Verified");
						 
						 if(domainParts.length-domainIndex==2){
								return 2;
							}
						 
						 /*
						  * If we reach this point, it means we successfully Verified DS from upper layer and DNSKEY from 
						  * lower layer
						  */
						 
						 /* It is time to forward the request to next level, but before we do that, we must get
						  * DS from current layer for example "xyz.com." like we did in root
						  */
						  
						 
						  prevDname = currDname;
						  if(--domainIndex >=0){
							   currDname = domainParts[domainIndex]+"."+prevDname;
						  }
						  else{
							  return 2;
						  }
						  
						  
						    dName = Name.fromString(currDname); 
							record = Record.newRecord(dName, Type.DNSKEY, DClass.IN);
						    query = Message.newQuery(record);
						 
						    response = simpleResolver.send(query); // use the same simpleResolver for r.rdataToString() 
						 
						    
						 // getting the DS from from the reply for updated query ("xyz.com" something")
						    
						  
						    Record[] xyz =response.getSectionArray(Section.AUTHORITY);
							for(Record r1: xyz){
								if(r1.getType()==Type.DS){
									 prevDS = (DSRecord) r1;
								}
							}
 
							return  helper(response);
					
					}
					catch (Exception ex){
						if(++count==rArray.length)
							return -1;
					}
				}
			}
			
			
		  return -1;	
	}
   static Message digHelper(Message response, Message query) throws IOException{
		
		while(true){
			//System.out.println(response.toString());
			Record[] rArray = response.getSectionArray(Section.AUTHORITY);
			if(rArray.length!=0){
				int count = 0;
				for(Record r: rArray){
					try{
						if(r.getType() == Type.SOA)
							return response;
						Resolver simpleResolver = new SimpleResolver(r.rdataToString());
						simpleResolver.setEDNS(0, 0, Flags.DO, null);
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
	static void buildRootList(String fname, List<String> rootList)throws FileNotFoundException, IOException{
		String line = null;
		
		FileReader fileReader = new FileReader(fname);
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		while((line=bufferedReader.readLine()) !=null){
			rootList.add(line);
		}
		
		bufferedReader.close();
	}
	
	
		
	
}
