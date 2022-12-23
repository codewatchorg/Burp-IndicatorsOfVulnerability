/*
 * Name:           Burp Indicators of Vulnerability
 * Version:        0.3.10
 * Date:           1/9/2020
 * Author:         Josh Berry - josh.berry@codewatch.org
 * Github:         https://github.com/codewatchorg/Burp-IndicatorsOfVulnerability
 * 
 * Description:    This plugin checks application responses and in some cases browser requests for indications of SQLi, XXE, and other vulnerabilities or attack points for these issues.
 * 
 * Contains regex work from SecretsFinder by m4110k: https://github.com/m4ll0k/BurpSuite-Secret_Finder
 *
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;
import java.awt.Component;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JCheckBox;
import javax.swing.JButton;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.ArrayList;
import javax.swing.JComboBox;

public class BurpExtender implements IBurpExtender, IScannerCheck, IHttpListener, ITab {

  // Setup extension wide variables
  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  private static final String burpIVVersion = "0.3.10";
  private static final Pattern SqlPattern = Pattern.compile("(SQL Server|MySQL|MariaDB|Postgres|Oracle|ORA\\-[0-9][0-9]|OLE DB Provider|JET Database|Type mismatch|error in your SQL|Invalid SQL|OLEDB Exception|ADODB|OLEDB Provider|OleDbException)", Pattern.CASE_INSENSITIVE);
  private static final Pattern SqlParamPattern = Pattern.compile("(row|table|grant|create|select|alter|delete|update|insert|column|field|^from|^to$|keyword|search|results|filter|sleep|fetch|query|sort|^sel$|select|where)", Pattern.CASE_INSENSITIVE);
  private static final Pattern XxePattern = Pattern.compile("(XML Reader error|java\\.xml\\.|UnmarshalException|Marshaller|Xml\\.XmlDocument|Xml\\.XmlDictionaryReader|Xml\\.XmlNodeReader|Xml\\.XmlReader|Xml\\.XmlTextReader|Xml\\.Xpath\\.XpathNavigator|Xsl\\.XslCompiledTransform|System\\.Xml|org\\.xml\\.|sax\\.XMLReader|DocumentBuilderFactory|SAXParserFactory|DOM4J|XmlInputFactory|TransformerFactory|validation\\.Validator|validation\\.SchemaFactory|SAXTransformerFactory)", Pattern.CASE_INSENSITIVE);
  private static final Pattern CgiPattern = Pattern.compile("(/cgi-bin/|/cgi-sys/|/cgi-mod/|[a-zA-Z0-9]*\\.cgi)", Pattern.CASE_INSENSITIVE);
  private static final Pattern CmdPattern = Pattern.compile("(exec|shell|run|cmd|daemon|ping|command|func|^arg$|process|function|^func$|payload)", Pattern.CASE_INSENSITIVE);
  private static final Pattern SerialPattern = Pattern.compile("(could\\s+not\\s+be\\s+deserialized|serialization\\s+failed|deserializ|serialization\\s+error|serialize\\(\\)|marshal\\.load|marshal\\.dump|unpickler|cpickle|ObjectInputStream\\.readUnshared|XStream\\.fromXML|XMLDecoder|ObjectInputStream\\.readObject|ObjectInputStream\\.defaultReadObject|LocateRegistry\\.createRegistry|Serialization\\.XmlSerializer|Serialization\\.DataContractSerializer|Serialization\\.NetDataContractSerializer|Serialization\\.JavaScriptSerializer|Serialization\\.Json\\.DataContractJsonSerializer|System\\.Resource\\.ResourceReader|Microsoft\\.Web\\.Design\\.Remote\\.ProxyObject|Newtonsoft\\.Json\\.JsonSerializationException|ServiceStack\\.Text|Binary\\.BinaryFormatter|Soap\\.SoapFormatter|UI\\.ObjectStateFormatter|Serialization\\.NetDataContractSerializer|UI\\.LosFormatter|Workflow\\.ComponentModel\\.Activity|SoapServerFormatterSinkProvider|SoapClientFormatterSinkProvider|BinaryServerFormatterSinkProvider|BinaryClientFormatterSinkProvider|SoapClientFormatterSink|SoapServerFormatterSink|BinaryClientFormatterSink|BinaryServerFormatterSink)", Pattern.CASE_INSENSITIVE);
  private static final Pattern SuspiciousPattern = Pattern.compile("(cfg|^conf$|config|dbg|debug|clone|enable|toggle|disable|load|test)", Pattern.CASE_INSENSITIVE);
  private static final Pattern SerialHeaderPattern = Pattern.compile("(x-java-serialized-object)", Pattern.CASE_INSENSITIVE);
  private static final Pattern JwtHeaderPattern = Pattern.compile("(Authorization:\\s+Bearer\\s+[A-Za-z0-9\\+/=_\\-\\.]+)", Pattern.CASE_INSENSITIVE);
  private static final Pattern FileHandlingPattern = Pattern.compile("(^doc$|^go$|goto|window|include|^inc$|prefix|locate|layout|document|callback|^dir$|directory|^dest$|destination|^feed$|html|domain|host|navigation|next|view|site|page|^pdf$|style|^img$|preview|^show$|activity|content|template|folder|^redir$|redirect|url|return|^file$|^image$|imagename|open|filename|^lang$|language|^home$|^homedir$)", Pattern.CASE_INSENSITIVE);
  private static final Pattern IdorHandlingPattern = Pattern.compile("(edit|profile|report|modify|[a-zA-Z0-9]id|^id$|group|user|order|number|^num$|account|key)", Pattern.CASE_INSENSITIVE);
  private static final Pattern SecretsPattern = Pattern.compile("(azure_storage_account|AZURE_STORAGE_ACCOUNT|azure_storage_access_key|AZURE_STORAGE_ACCESS_KEY|S3_KEY|S3_SECRET|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AccessKeyId|SecretAccessKey|aws_access_key_id|aws_secret_access_key|aws_session_token|s3_key|s3_secret|accesskeyid|secretaccesskey|BEGIN RSA PRIVATE KEY|BEGIN DSA PRIVATE KEY|BEGIN EC PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|ya29\\.[0-9A-Za-z\\-_]+|A3T[A-Z0-9]|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AGPA[A-Z0-9]{16}|AIDA[A-Z0-9]{16}|AROA[A-Z0-9]{16}|AIPA[A-Z0-9]{16}|ANPA[A-Z0-9]{16}|ANVA[A-Z0-9]{16}|amzn\\\\.mws\\\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|EAACEdEose0cBA[0-9A-Za-z]+|key-[0-9a-zA-Z]{32}|SK[0-9a-fA-F]{32}|access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}|sq0csp-[ 0-9A-Za-z\\-_]{43}|sqOatp-[0-9A-Za-z\\-_]{22}|sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24}|[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*)");
  private static final Pattern S3BucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.s3[\\w.-]*\\.amazonaws\\.com|s3(?:[\\w.-]*\\.amazonaws\\.com(?:(?::\\d+)?\\\\?/)*|://)([\\w.-]+))(?:(?::\\d+)?\\\\?/)?(?:.*?\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern GoogleBucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.storage[\\w-]*\\.googleapis\\.com|(?:(?:console\\.cloud\\.google\\.com/storage/browser/|storage[\\w-]*\\.googleapis\\.com)(?:(?::\\d+)?\\\\?/)*|gs://)([\\w.-]+))(?:(?::\\d+)?\\\\?/([^\\s?#]*))?(?:.*\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureBucketPattern = Pattern.compile("(([\\w.-]+\\.blob\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern FileValuePattern = Pattern.compile("(\\.xml$|\\.doc$|\\.docx$|\\.xls$|\\.xlsx$|\\.ppt$|\\.pptx$|\\.pdf$|\\.html$|\\.htm$|\\.js$|\\.json$|^http\\://|^https\\://|^ftp\\://|^file\\://|^php\\://|^jar\\://|^www\\.|^www1\\.|^www2\\.|^www3\\.|^ww1\\.|^ww2\\.|^ww3\\.)", Pattern.CASE_INSENSITIVE);
  private static final Pattern GcpFirebasePattern = Pattern.compile("([\\w.-]+\\.firebaseio\\.com)", Pattern.CASE_INSENSITIVE );
  private static final Pattern GcpFirestorePattern = Pattern.compile("(firestore\\.googleapis\\.com.*)", Pattern.CASE_INSENSITIVE );
  private static final Pattern AzureTablePattern = Pattern.compile("(([\\w.-]+\\.table\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureQueuePattern = Pattern.compile("(([\\w.-]+\\.queue\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureFilePattern = Pattern.compile("(([\\w.-]+\\.file\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureCosmosPattern = Pattern.compile("(([\\w.-]+\\.documents\\.azure\\.com(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern CloudFrontPattern = Pattern.compile("([\\w.-]+\\.cloudfront\\.net)", Pattern.CASE_INSENSITIVE );
  private static final Pattern SubdomainTakeoverPattern = Pattern.compile("(NoSuchBucket|The specified bucket does not exist|herokucdn\\\\.com\\\\/error-pages\\\\/no-such-app\\\\.html|There isn't a GitHub Pages site here\\\\.|Do you want to register <em>[\\\\w.-]*\\\\.wordpress\\\\.com<\\\\/em>\\\\?|Sorry, this shop is currently unavailable|Repository not found|Whatever you were looking for doesn't currently exist at this address)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AspPattern = Pattern.compile("(\\.ASPXAUTH|__VIEWSTATE|.AspNet.ApplicationCookie)");
  private static final Pattern ProtoPollutionPattern = Pattern.compile("(object\\.assign\\(|object-path-set|function merge\\(|function clone\\(|function extend\\()", Pattern.CASE_INSENSITIVE );
  private static final Pattern ParseServerPattern = Pattern.compile("(X\\-Parse\\-Application\\-Id:)", Pattern.CASE_INSENSITIVE);
  private Boolean isSqliDbPatternEnabled = true;
  private int SqliDbCounter = 0;
  private Boolean isSqliParamPatternEnabled = false;
  private int SqliParamCounter = 0;
  private Boolean isXxePatternEnabled = true;
  private int XxeCounter = 0;
  private Boolean isCgiPatternEnabled = false;
  private int CgiCounter = 0;
  private Boolean isCmdPatternEnabled = false;
  private int CmdCounter = 0;
  private Boolean isSerialPatternEnabled = true;
  private int SerialCounter = 0;
  private Boolean isSuspiciousPatternEnabled = false;
  private int SuspiciousCounter = 0;
  private Boolean isJwtPatternEnabled = false;
  private int JwtCounter = 0;
  private Boolean isFilePatternEnabled = false;
  private int FileCounter = 0;
  private Boolean isIdorPatternEnabled = false;
  private int IdorCounter = 0;
  private Boolean isCloudPatternEnabled = false;
  private Boolean isSecretsPatternEnabled = true;
  private int SecretsCounter = 0;
  private Boolean isSubdomainPatternEnabled = true;
  private int SubdomainCounter = 0;
  private Boolean isAspDotNetPatternEnabled = false;
  private int AspDotNetCounter = 0;
  private Boolean isPrototypePatternEnabled = false;
  private int PrototypeCounter = 0;
  private Boolean isParsePatternEnabled = true;
  private int ParseCounter = 0;
  private final List<Integer> countAmount = Arrays.asList(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
  private int countConfig = 20;
  private PrintWriter printOut;
  public JPanel IovPanel;

  // Basic extension setup
  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    extCallbacks = callbacks;
    extHelpers = extCallbacks.getHelpers();
    extCallbacks.setExtensionName("Indicators of Vulnerability");
    printOut = new PrintWriter(extCallbacks.getStdout(), true);
    extCallbacks.registerHttpListener(this);
    extCallbacks.registerScannerCheck(this);
    
    // Create a tab to configure credential values
    IovPanel = new JPanel(null);
    JLabel IovSqliDbLabel = new JLabel();
    JLabel IovSqliDbDescLabel = new JLabel();
    final JCheckBox IovSqliDbCheck = new JCheckBox();
    IovSqliDbCheck.setSelected(true);
    JLabel IovSqliParamLabel = new JLabel();
    JLabel IovSqliParamDescLabel = new JLabel();
    final JCheckBox IovSqliParamCheck = new JCheckBox();
    JLabel IovXxeLabel = new JLabel();
    JLabel IovXxeDescLabel = new JLabel();
    final JCheckBox IovXxeCheck = new JCheckBox();
    IovXxeCheck.setSelected(true);
    JLabel IovCgiLabel = new JLabel();
    JLabel IovCgiDescLabel = new JLabel();
    final JCheckBox IovCgiCheck = new JCheckBox();
    JLabel IovCmdLabel = new JLabel();
    JLabel IovCmdDescLabel = new JLabel();
    final JCheckBox IovCmdCheck = new JCheckBox();
    JLabel IovSerialLabel = new JLabel();
    JLabel IovSerialDescLabel = new JLabel();
    final JCheckBox IovSerialCheck = new JCheckBox();
    IovSerialCheck.setSelected(true);
    JLabel IovSuspiciousLabel = new JLabel();
    JLabel IovSuspiciousDescLabel = new JLabel();
    final JCheckBox IovSuspiciousCheck = new JCheckBox();
    JLabel IovJwtLabel = new JLabel();
    JLabel IovJwtDescLabel = new JLabel();
    final JCheckBox IovJwtCheck = new JCheckBox();
    JLabel IovFileLabel = new JLabel();
    JLabel IovFileDescLabel = new JLabel();
    final JCheckBox IovFileCheck = new JCheckBox();
    JLabel IovIdorLabel = new JLabel();
    JLabel IovIdorDescLabel = new JLabel();
    final JCheckBox IovIdorCheck = new JCheckBox();
    JLabel IovCloudLabel = new JLabel();
    JLabel IovCloudDescLabel = new JLabel();
    final JCheckBox IovCloudCheck = new JCheckBox();
    JLabel IovSecretsLabel = new JLabel();
    JLabel IovSecretsDescLabel = new JLabel();
    final JCheckBox IovSecretsCheck = new JCheckBox();
    IovSecretsCheck.setSelected(true);
    JLabel IovSubdomainLabel = new JLabel();
    JLabel IovSubdomainDescLabel = new JLabel();
    final JCheckBox IovSubdomainCheck = new JCheckBox();
    IovSubdomainCheck.setSelected(true);
    JLabel IovAspDotNetLabel = new JLabel();
    JLabel IovAspDotNetDescLabel = new JLabel();
    final JCheckBox IovAspDotNetCheck = new JCheckBox();
    JLabel IovPrototypeLabel = new JLabel();
    JLabel IovPrototypeDescLabel = new JLabel();
    final JCheckBox IovPrototypeCheck = new JCheckBox();
    JLabel IovParseLabel = new JLabel();
    JLabel IovParseDescLabel = new JLabel();
    final JCheckBox IovParseCheck = new JCheckBox();
    IovParseCheck.setSelected(true);
    JLabel IovCountLabel = new JLabel();
    JLabel IovCountDescLabel = new JLabel();
    final JComboBox countAmountCbx = new JComboBox(countAmount.toArray());
    countAmountCbx.setSelectedIndex(1);
    JButton IovSetConfigBtn = new JButton("Set Configuration");
    JLabel IovSetConfigDescLabel = new JLabel();
    
    // Set values for labels, panels, locations, for IoV stuff
    // SQLi database errors / responses checks
    IovSqliDbLabel.setText("SQLi Resp Checks:");
    IovSqliDbDescLabel.setText("Errors / Information in responses indicating SQLi.");
    IovSqliDbLabel.setBounds(16, 15, 145, 20);
    IovSqliDbCheck.setBounds(166, 12, 20, 26);
    IovSqliDbDescLabel.setBounds(606, 15, 600, 20);
    
    // SQLi parameter checks
    IovSqliParamLabel.setText("SQLi Param Checks:");
    IovSqliParamDescLabel.setText("Parameters to target for SQLi.");
    IovSqliParamLabel.setBounds(16, 50, 145, 20);
    IovSqliParamCheck.setBounds(166, 47, 20, 26);
    IovSqliParamDescLabel.setBounds(606, 50, 600, 20);
    
    // XXE response checks
    IovXxeLabel.setText("XXE Resp Checks:");
    IovXxeDescLabel.setText("Errors / Information in responses indicating XXE.");
    IovXxeLabel.setBounds(16, 85, 145, 20);
    IovXxeCheck.setBounds(166, 82, 20, 26);
    IovXxeDescLabel.setBounds(606, 85, 600, 20);
    
    // CGI response checks
    IovCgiLabel.setText("CGI Resp Checks:");
    IovCgiDescLabel.setText("CGI resource usage.");
    IovCgiLabel.setBounds(16, 120, 145, 20);
    IovCgiCheck.setBounds(166, 117, 20, 26);
    IovCgiDescLabel.setBounds(606, 120, 600, 20);
    
    // CMDi parameter checks
    IovCmdLabel.setText("CMDi Param Checks:");
    IovCmdDescLabel.setText("Parameters to target for CMDi.");
    IovCmdLabel.setBounds(16, 155, 145, 20);
    IovCmdCheck.setBounds(166, 152, 20, 26);
    IovCmdDescLabel.setBounds(606, 155, 600, 20);
    
    // Serialization response checks
    IovSerialLabel.setText("Serialization Checks:");
    IovSerialDescLabel.setText("Errors / Information in responses indicating serialization vulns.");
    IovSerialLabel.setBounds(16, 190, 145, 20);
    IovSerialCheck.setBounds(166, 187, 20, 26);
    IovSerialDescLabel.setBounds(606, 190, 600, 20);
    
    // Suspicious parameters checks
    IovSuspiciousLabel.setText("Suspicious Param Checks:");
    IovSuspiciousDescLabel.setText("Suspcious parameter names.");
    IovSuspiciousLabel.setBounds(16, 225, 145, 20);
    IovSuspiciousCheck.setBounds(166, 222, 20, 26);
    IovSuspiciousDescLabel.setBounds(606, 225, 600, 20);
    
    // JWT response checks
    IovJwtLabel.setText("JWT Resp Checks:");
    IovJwtDescLabel.setText("JWT usage.");
    IovJwtLabel.setBounds(16, 260, 145, 20);
    IovJwtCheck.setBounds(166, 257, 20, 26);
    IovJwtDescLabel.setBounds(606, 260, 600, 20);
    
    // File parameter checks
    IovFileLabel.setText("File Param Checks:");
    IovFileDescLabel.setText("Files, folders, and document parameters to target for LFI/RFI/SSRF/etc.");
    IovFileLabel.setBounds(16, 295, 145, 20);
    IovFileCheck.setBounds(166, 292, 20, 26);
    IovFileDescLabel.setBounds(606, 295, 600, 20);
    
    // IDOR parameter checks
    IovIdorLabel.setText("IDOR Param Checks:");
    IovIdorDescLabel.setText("Parameters to target for IDOR.");
    IovIdorLabel.setBounds(16, 330, 145, 20);
    IovIdorCheck.setBounds(166, 327, 20, 26);
    IovIdorDescLabel.setBounds(606, 330, 600, 20);
    
    // Cloud resource parameter checks
    IovCloudLabel.setText("Cloud Resp Checks:");
    IovCloudDescLabel.setText("AWS / Azure / GCP / Cloudfront usage (redundant with AnonymousCloud extension).");
    IovCloudLabel.setBounds(16, 365, 145, 20);
    IovCloudCheck.setBounds(166, 362, 20, 26);
    IovCloudDescLabel.setBounds(606, 365, 600, 20);
    
    // Secrets in responses checks
    IovSecretsLabel.setText("Secrets Resp Checks:");
    IovSecretsDescLabel.setText("Secrets observed in application responses.");
    IovSecretsLabel.setBounds(16, 400, 145, 20);
    IovSecretsCheck.setBounds(166, 397, 20, 26);
    IovSecretsDescLabel.setBounds(606, 400, 600, 20);
    
    // Subdomain response checks
    IovSubdomainLabel.setText("Subdomain Resp Checks:");
    IovSubdomainDescLabel.setText("Errors indicating the app is a subdomain for potential takeover.");
    IovSubdomainLabel.setBounds(16, 435, 145, 20);
    IovSubdomainCheck.setBounds(166, 432, 20, 26);
    IovSubdomainDescLabel.setBounds(606, 435, 600, 20);
    
    // ASP.NET usage checks
    IovAspDotNetLabel.setText("ASP.Net Resp Checks:");
    IovAspDotNetDescLabel.setText("ASP.NET usage.");
    IovAspDotNetLabel.setBounds(16, 470, 145, 20);
    IovAspDotNetCheck.setBounds(166, 467, 20, 26);
    IovAspDotNetDescLabel.setBounds(606, 470, 600, 20);
    
    // Prototype pollution checks
    IovPrototypeLabel.setText("Prototype Param Checks:");
    IovPrototypeDescLabel.setText("Parameters and functions to target for prototype pollution.");
    IovPrototypeLabel.setBounds(16, 505, 145, 20);
    IovPrototypeCheck.setBounds(166, 502, 20, 26);
    IovPrototypeDescLabel.setBounds(606, 505, 600, 20);
    
    // Parse server response checks
    IovParseLabel.setText("Parse Resp Checks:");
    IovParseDescLabel.setText("Application responses indicate a Parse server is in use.");
    IovParseLabel.setBounds(16, 540, 145, 20);
    IovParseCheck.setBounds(166, 537, 20, 26);
    IovParseDescLabel.setBounds(606, 540, 600, 20);
    
    // Number of findings to report per group
    IovCountLabel.setText("Checks to Report:");
    IovCountDescLabel.setText("Sets the max # of findings to report per group (ignored for cloud resources).");
    IovCountLabel.setBounds(16, 575, 145, 20);
    countAmountCbx.setBounds(166, 572, 75, 26);
    IovCountDescLabel.setBounds(606, 575, 600, 20);
    
    // Create button for setting options
    IovSetConfigDescLabel.setText("Enable configuration.");
    IovSetConfigDescLabel.setBounds(606, 610, 600, 20);
    IovSetConfigBtn.setBounds(166, 607, 310, 26);
    
    
    // Process and set configuration options
    IovSetConfigBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
          
        // Check for SQL db error checks being enabled
        if (IovSqliDbCheck.isSelected()) {
            isSqliDbPatternEnabled = true;
        } else {
            isSqliDbPatternEnabled = false;
        }
        
        // Check for SQL db parameter checks being enabled
        if (IovSqliParamCheck.isSelected()) {
            isSqliParamPatternEnabled = true;
        } else {
            isSqliParamPatternEnabled = false;
        }
        
        // Check for SQL XXE error checks being enabled
        if (IovXxeCheck.isSelected()) {
            isXxePatternEnabled = true;
        } else {
            isXxePatternEnabled = false;
        }
        
        // Check for CGI checks being enabled
        if (IovCgiCheck.isSelected()) {
            isCgiPatternEnabled = true;
        } else {
            isCgiPatternEnabled = false;
        }
        
        // Check for command injection parameter checks being enabled
        if (IovCmdCheck.isSelected()) {
            isCmdPatternEnabled = true;
        } else {
            isCmdPatternEnabled = false;
        }
        
        // Check for serialization error checks being enabled
        if (IovSerialCheck.isSelected()) {
            isSerialPatternEnabled = true;
        } else {
            isSerialPatternEnabled = false;
        }
        
        // Check for suspicious parameter checks being enabled
        if (IovSuspiciousCheck.isSelected()) {
            isSuspiciousPatternEnabled = true;
        } else {
            isSuspiciousPatternEnabled = false;
        }
        
        // Check for JWT header checks being enabled
        if (IovJwtCheck.isSelected()) {
            isJwtPatternEnabled = true;
        } else {
            isJwtPatternEnabled = false;
        }
        
        // Check for file parameter checks being enabled
        if (IovFileCheck.isSelected()) {
            isFilePatternEnabled = true;
        } else {
            isFilePatternEnabled = false;
        }
        
        // Check for IDOR parameter checks being enabled
        if (IovIdorCheck.isSelected()) {
            isIdorPatternEnabled = true;
        } else {
            isIdorPatternEnabled = false;
        }
        
        // Check for cloud checks being enabled
        if (IovCloudCheck.isSelected()) {
            isCloudPatternEnabled = true;
        } else {
            isCloudPatternEnabled = false;
        }
        
        // Check for secrets in responses checks being enabled
        if (IovSecretsCheck.isSelected()) {
            isSecretsPatternEnabled = true;
        } else {
            isSecretsPatternEnabled = false;
        }
        
        // Check for subdomain error checks being enabled
        if (IovSubdomainCheck.isSelected()) {
            isSubdomainPatternEnabled = true;
        } else {
            isSubdomainPatternEnabled = false;
        }
        
        // Check for ASP.NET use indicator checks being enabled
        if (IovAspDotNetCheck.isSelected()) {
            isAspDotNetPatternEnabled = true;
        } else {
            isAspDotNetPatternEnabled = false;
        }
        
        // Check for prototype pollution indicator checks being enabled
        if (IovPrototypeCheck.isSelected()) {
            isPrototypePatternEnabled = true;
        } else {
            isPrototypePatternEnabled = false;
        }
        
        // Check for Parse server header checks being enabled
        if (IovParseCheck.isSelected()) {
            isParsePatternEnabled = true;
        } else {
            isParsePatternEnabled = false;
        }
        
        // Set max number of findings to capture
        countConfig = Integer.parseInt(countAmountCbx.getSelectedItem().toString());
        printOut.println("Configured to capture up to: " + countConfig + " results per category.");
      }
    });
    
    // Add labels and fields to tab
    IovPanel.add(IovSqliDbLabel);
    IovPanel.add(IovSqliDbDescLabel);
    IovPanel.add(IovSqliDbCheck);
    IovPanel.add(IovSqliParamLabel);
    IovPanel.add(IovSqliParamDescLabel);
    IovPanel.add(IovSqliParamCheck);
    IovPanel.add(IovXxeLabel);
    IovPanel.add(IovXxeDescLabel);
    IovPanel.add(IovXxeCheck);
    IovPanel.add(IovCgiLabel);
    IovPanel.add(IovCgiDescLabel);
    IovPanel.add(IovCgiCheck);
    IovPanel.add(IovCmdLabel);
    IovPanel.add(IovCmdDescLabel);
    IovPanel.add(IovCmdCheck);
    IovPanel.add(IovSerialLabel);
    IovPanel.add(IovSerialDescLabel);
    IovPanel.add(IovSerialCheck);
    IovPanel.add(IovSuspiciousLabel);
    IovPanel.add(IovSuspiciousDescLabel);
    IovPanel.add(IovSuspiciousCheck);
    IovPanel.add(IovJwtLabel);
    IovPanel.add(IovJwtDescLabel);
    IovPanel.add(IovJwtCheck);
    IovPanel.add(IovFileLabel);
    IovPanel.add(IovFileDescLabel);
    IovPanel.add(IovFileCheck);
    IovPanel.add(IovIdorLabel);
    IovPanel.add(IovIdorDescLabel);
    IovPanel.add(IovIdorCheck);
    IovPanel.add(IovCloudLabel);
    IovPanel.add(IovCloudDescLabel);
    IovPanel.add(IovCloudCheck);
    IovPanel.add(IovSecretsLabel);
    IovPanel.add(IovSecretsDescLabel);
    IovPanel.add(IovSecretsCheck);
    IovPanel.add(IovSubdomainLabel);
    IovPanel.add(IovSubdomainDescLabel);
    IovPanel.add(IovSubdomainCheck);
    IovPanel.add(IovAspDotNetLabel);
    IovPanel.add(IovAspDotNetDescLabel);
    IovPanel.add(IovAspDotNetCheck);
    IovPanel.add(IovPrototypeLabel);
    IovPanel.add(IovPrototypeDescLabel);
    IovPanel.add(IovPrototypeCheck);
    IovPanel.add(IovParseLabel);
    IovPanel.add(IovParseDescLabel);
    IovPanel.add(IovParseCheck);
    IovPanel.add(IovCountLabel);
    IovPanel.add(IovCountDescLabel);
    IovPanel.add(countAmountCbx);
    IovPanel.add(IovSetConfigBtn);
    IovPanel.add(IovSetConfigDescLabel);
    
    // Print extension header
    printHeader();   
    
    // Add the tab to Burp
    extCallbacks.customizeUiComponent(IovPanel);
    extCallbacks.addSuiteTab(BurpExtender.this);
  }
  
  // Tab caption
  @Override
  public String getTabCaption() { return "IoV"; }

  // Java component to return to Burp
  @Override
  public Component getUiComponent() { return IovPanel; }
  
  // Print to extension output tab
  public void printHeader() {
    printOut.println("Indicators of Vulnerability: " + burpIVVersion + "\n====================\nMonitor requests and responses for common indicators of SQLi, CMDi, XXE, Serialization, SSRF, SSTI, LFI, RFI, and Directory Traversal issues.\n\n"
      + "josh.berry@codewatch.org\n\n");
  }
  
  // Generate random strings for write test
  public String genRandStr() {
    int leftLimit = 48; // numeral '0'
    int rightLimit = 122; // letter 'z'
    int targetStringLength = 12;
    Random random = new Random();
 
    String generatedString = random.ints(leftLimit, rightLimit + 1)
      .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
      .limit(targetStringLength)
      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
      .toString();
 
    return generatedString;
  }
  
  // Perform a passive check for cloud buckets
  @Override
  public List<IScanIssue> doPassiveScan(IHttpRequestResponse messageInfo) {
    // Only process requests if the URL is in scope
    String checkUrl = extHelpers.analyzeRequest(messageInfo).getUrl().toString();
    if (extCallbacks.isInScope(extHelpers.analyzeRequest(messageInfo).getUrl()) && !checkUrl.endsWith(".jpg") && 
            !checkUrl.endsWith(".png") && !checkUrl.endsWith(".gif") && !checkUrl.endsWith(".ico") && 
            !checkUrl.endsWith(".css") && !checkUrl.endsWith(".mpg") && !checkUrl.endsWith(".mpeg") &&
            !checkUrl.endsWith(".mp4") && !checkUrl.endsWith(".woff") && !checkUrl.endsWith(".woff2") &&
            !checkUrl.endsWith(".jpeg")) {

      // Setup default request variables for URL and body
      IRequestInfo requestInfo = extHelpers.analyzeRequest(messageInfo);
      String reqUrl = requestInfo.getUrl().toString();
      String resp = new String(messageInfo.getResponse());
      String respBody = resp.substring(extHelpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset());
      String reqRaw = new String(messageInfo.getRequest());
      String reqBody = reqRaw.substring(requestInfo.getBodyOffset());
      
      // Check responses for cloud and other issues
     
      // Create an issue if we match any of the potential sources of attack for
      // CMDi a-la ShellShock. More to be added later. These are areas to focus these attacks,
      // not confirmed vulnerabilities.  
      if (isSerialPatternEnabled && SerialCounter < countConfig) {
        Matcher SerialRespMatch = SerialHeaderPattern.matcher(resp);
        Matcher SerialReqMatch = SerialHeaderPattern.matcher(reqRaw);
        
        // Create an issue if we match any of the indicators for a serialized object in the response
        if (SerialRespMatch.find()) {
            List<int[]> SerialRespMatches = getMatches(messageInfo.getResponse(), SerialRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, SerialRespMatches, "[IoV] Serialization Indicator of Vulnerability", "The response contained the following text: " + SerialRespMatch.group(0), "Information", "Tentative");
            SerialCounter++;
        }
      
        // Create an issue if we match any of the indicators for a serialized object in the request
        if (SerialReqMatch.find()) {
            List<int[]> SerialReqMatches = getMatches(messageInfo.getRequest(), SerialReqMatch.group(0).getBytes());
            reportIssue(messageInfo, SerialReqMatches, null, "[IoV] Serialization Indicator of Vulnerability", "The request contained the following header: " + SerialReqMatch.group(0), "Information", "Tentative");
            SerialCounter++;
        }
      }
      
      if (isJwtPatternEnabled && JwtCounter < countConfig) {
        Matcher JwtReqMatch = JwtHeaderPattern.matcher(reqRaw);
        
        // If using JWT tokens, might be using defaults/known secrets in the request
        if (JwtReqMatch.find()) {
            List<int[]> JwtReqMatches = getMatches(messageInfo.getRequest(), JwtReqMatch.group(0).getBytes());
            reportIssue(messageInfo, JwtReqMatches, null, "[IoV] JWT in Use - Check for Known JWT Secrets", "The request contained the following JWT header: " + JwtReqMatch.group(0) + "<BR><BR>See the following for more details: https://github.com/BBhacKing/jwt_secrets and https://github.com/wallarm/jwt-secrets.", "Information", "Tentative");
            JwtCounter++;
        }
      }
      
      if (isAspDotNetPatternEnabled && AspDotNetCounter < countConfig) {
        Matcher AspRespMatch = AspPattern.matcher(resp);
        // Create an issue if there was a match that indicates to check for use of pre-published keys
        if (AspRespMatch.find()) {
            List<int[]> aspValidationMatches = getMatches(messageInfo.getResponse(), AspRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, aspValidationMatches, "[IoV] ASP.NET .ASPXAUTH/__VIEWSTATE/.AspNet.ApplicationCookie in Use - Check for Pre-Published MachineKeys", "The response contained the following ASP.NET MachineKey indicator: " + AspRespMatch.group(0) + "<BR><BR>See the following for more details: https://www.notsosecure.com/project-blacklist3r/.", "Information", "Tentative");
            AspDotNetCounter++;
        }  
      }
      
      if (isCgiPatternEnabled && CgiCounter < countConfig) {
        Matcher CgiUrlMatch = CgiPattern.matcher(reqUrl);
        
        if (CgiUrlMatch.find()) {
            List<int[]> CgiUrlMatches = getMatches(messageInfo.getRequest(), CgiUrlMatch.group(0).getBytes());
            reportIssue(messageInfo, CgiUrlMatches, null, "[IoV] Target for ShellShock CMDi", "The URL contained the following path/file: " + CgiUrlMatch.group(0), "Information", "Tentative");
            CgiCounter++;
        }
      }
      
      if (isCloudPatternEnabled) {
        Matcher S3BucketUrlMatch = S3BucketPattern.matcher(reqUrl);
        Matcher S3BucketBodyMatch = S3BucketPattern.matcher(reqBody);
        Matcher GoogleBucketUrlMatch = GoogleBucketPattern.matcher(reqUrl);
        Matcher GoogleBucketBodyMatch = GoogleBucketPattern.matcher(reqBody);
        Matcher AzureBucketUrlMatch = AzureBucketPattern.matcher(reqUrl);
        Matcher AzureBucketBodyMatch = AzureBucketPattern.matcher(reqBody);
        Matcher AzureTableMatch = AzureTablePattern.matcher(reqBody);
        Matcher AzureQueueMatch = AzureQueuePattern.matcher(reqBody);
        Matcher AzureFileMatch = AzureFilePattern.matcher(reqBody);
        Matcher AzureCosmosMatch = AzureCosmosPattern.matcher(reqBody);
        Matcher S3BucketRespMatch = S3BucketPattern.matcher(respBody);
        Matcher GoogleBucketRespMatch = GoogleBucketPattern.matcher(respBody);
        Matcher AzureBucketRespMatch = AzureBucketPattern.matcher(respBody);
        Matcher AzureTableRespMatch = AzureTablePattern.matcher(respBody);
        Matcher AzureQueueRespMatch = AzureQueuePattern.matcher(respBody);
        Matcher AzureFileRespMatch = AzureFilePattern.matcher(respBody);
        Matcher AzureCosmosRespMatch = AzureCosmosPattern.matcher(respBody);
        Matcher GcpFirebaseRespMatch = GcpFirebasePattern.matcher(respBody);
        Matcher GcpFirestoreRespMatch = GcpFirestorePattern.matcher(respBody);
        Matcher CloudFrontRespMatch = CloudFrontPattern.matcher(respBody);
        
        // Create an issue noting an AWS S3 Bucket was identified in the URL
        if (S3BucketUrlMatch.find()) {
            List<int[]> S3BucketUrlMatches = getMatches(messageInfo.getRequest(), S3BucketUrlMatch.group(0).getBytes());
            reportIssue(messageInfo, S3BucketUrlMatches, null, "[IoV] AWS S3 Bucket Identified", "The URL contained the following bucket: " + S3BucketUrlMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting a Google Bucket was identified in the URL
        if (GoogleBucketUrlMatch.find()) {
            List<int[]> GoogleBucketUrlMatches = getMatches(messageInfo.getRequest(), GoogleBucketUrlMatch.group(0).getBytes());
            reportIssue(messageInfo, GoogleBucketUrlMatches, null, "[IoV] Google Storage Bucket Identified", "The URL contained the following bucket: " + GoogleBucketUrlMatch.group(0), "Information", "Firm");
        }

        // Create an issue noting an Azure Bucket was identified in the URL
        if (AzureBucketUrlMatch.find()) {
            List<int[]> AzureBucketUrlMatches = getMatches(messageInfo.getRequest(), AzureBucketUrlMatch.group(0).getBytes());
            reportIssue(messageInfo, AzureBucketUrlMatches, null, "[IoV] Azure Storage Container Identified", "The URL contained the following bucket: " + AzureBucketUrlMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an AWS S3 Bucket was identified in the request
        if (S3BucketBodyMatch.find()) {
            List<int[]> S3BucketBodyMatches = getMatches(messageInfo.getRequest(), S3BucketBodyMatch.group(0).getBytes());
            reportIssue(messageInfo, S3BucketBodyMatches, null, "[IoV] AWS S3 Bucket Identified", "The request body contained the following bucket: " + S3BucketBodyMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting a Google Bucket was identified in the request
        if (GoogleBucketBodyMatch.find()) {
            List<int[]> GoogleBucketBodyMatches = getMatches(messageInfo.getRequest(), GoogleBucketBodyMatch.group(0).getBytes());
            reportIssue(messageInfo, GoogleBucketBodyMatches, null, "[IoV] Google Storage Bucket Identified", "The request body contained the following bucket: " + GoogleBucketBodyMatch.group(0), "Information", "Firm");
        }

        // Create an issue noting an Azure Bucket was identified in the request
        if (AzureBucketBodyMatch.find()) {
            List<int[]> AzureBucketBodyMatches = getMatches(messageInfo.getRequest(), AzureBucketBodyMatch.group(0).getBytes());
            reportIssue(messageInfo, AzureBucketBodyMatches, null, "[IoV] Azure Storage Container Identified", "The request body contained the following bucket: " + AzureBucketBodyMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Table was identified in the request
        if (AzureTableMatch.find()) {
            List<int[]> AzureTableMatches = getMatches(messageInfo.getRequest(), AzureTableMatch.group(0).getBytes());
            reportIssue(messageInfo, AzureTableMatches, null, "[IoV] Azure Storage Container Identified - Table", "The request body contained the following table: " + AzureTableMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Queue was identified in the request
        if (AzureQueueMatch.find()) {
            List<int[]> AzureQueueMatches = getMatches(messageInfo.getRequest(), AzureQueueMatch.group(0).getBytes());
            reportIssue(messageInfo, AzureQueueMatches, null, "[IoV] Azure Storage Container Identified - Queue", "The request body contained the following queue: " + AzureQueueMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Share was identified in the request
        if (AzureFileMatch.find()) {
            List<int[]> AzureFileMatches = getMatches(messageInfo.getRequest(), AzureFileMatch.group(0).getBytes());
            reportIssue(messageInfo, AzureFileMatches, null, "[IoV] Azure Storage Container Identified - Share", "The request body contained the following share: " + AzureFileMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Cosmos DB was identified in the request
        if (AzureCosmosMatch.find()) {
            List<int[]> AzureCosmosMatches = getMatches(messageInfo.getRequest(), AzureCosmosMatch.group(0).getBytes());
            reportIssue(messageInfo, AzureCosmosMatches, null, "[IoV] Azure Cosmos Database Identified", "The request body contained the following Cosmos DB: " + AzureCosmosMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an AWS S3 Bucket was identified in the response
        if (S3BucketRespMatch.find()) {
            List<int[]> S3BucketRespMatches = getMatches(messageInfo.getResponse(), S3BucketRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, S3BucketRespMatches, "[IoV] AWS S3 Bucket Identified", "The response body contained the following bucket: " + S3BucketRespMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting a Google Bucket was identified in the response
        if (GoogleBucketRespMatch.find()) {
            List<int[]> GoogleBucketRespMatches = getMatches(messageInfo.getResponse(), GoogleBucketRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, GoogleBucketRespMatches, "[IoV] Google Storage Bucket Identified", "The response body contained the following bucket: " + GoogleBucketRespMatch.group(0), "Information", "Firm");
        }

        // Create an issue noting an Azure Bucket was identified in the response
        if (AzureBucketRespMatch.find()) {
            List<int[]> AzureBucketRespMatches = getMatches(messageInfo.getResponse(), AzureBucketRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, AzureBucketRespMatches, "[IoV] Azure Storage Container Identified", "The response body contained the following bucket: " + AzureBucketRespMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Table was identified in the response
        if (AzureTableRespMatch.find()) {
            List<int[]> AzureTableRespMatches = getMatches(messageInfo.getResponse(), AzureTableRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, AzureTableRespMatches, "[IoV] Azure Storage Container Identified - Table", "The response body contained the following table: " + AzureTableRespMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Queue was identified in the response
        if (AzureQueueRespMatch.find()) {
            List<int[]> AzureQueueRespMatches = getMatches(messageInfo.getResponse(), AzureQueueRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, AzureQueueRespMatches, "[IoV] Azure Storage Container Identified - Queue", "The response body contained the following queue: " + AzureQueueRespMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Share was identified in the response
        if (AzureFileRespMatch.find()) {
            List<int[]> AzureFileRespMatches = getMatches(messageInfo.getResponse(), AzureFileRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, AzureFileRespMatches, "[IoV] Azure Storage Container Identified - Share", "The response body contained the following share: " + AzureFileRespMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting an Azure Cosmos DB was identified in the response
        if (AzureCosmosRespMatch.find()) {
            List<int[]> AzureCosmosRespMatches = getMatches(messageInfo.getResponse(), AzureCosmosRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, AzureCosmosRespMatches, "[IoV] Azure Cosmos Database Identified", "The response body contained the following Cosmos DB: " + AzureCosmosRespMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting a Firebase.io database was identified in the response
        if (GcpFirebaseRespMatch.find()) {
            List<int[]> GcpFirebaseRespMatches = getMatches(messageInfo.getResponse(), GcpFirebaseRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, GcpFirebaseRespMatches, "[IoV] Firebase Database Identified", "The response body contained the following Firebase DB: " + GcpFirebaseRespMatch.group(0), "Information", "Firm");
        }
      
        // Create an issue noting a Firestore database was identified in the response
        if (GcpFirestoreRespMatch.find()) {
            List<int[]> GcpFirestoreRespMatches = getMatches(messageInfo.getResponse(), GcpFirestoreRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, GcpFirestoreRespMatches, "[IoV] Firestore Database Identified", "The response body contained the following Firestore DB: " + GcpFirestoreRespMatch.group(0), "Information", "Firm");
        }
        
        // Create an issue noting a Cloudfront resource was identified in the response
        if (CloudFrontRespMatch.find()) {
            List<int[]> CloudFrontRespMatches = getMatches(messageInfo.getResponse(), CloudFrontRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, CloudFrontRespMatches, "[IoV] Cloudfront Resource Identified", "The response body contained the following Cloudfront URL: " + CloudFrontRespMatch.group(0), "Information", "Firm");
        }
      }
      
      if (isPrototypePatternEnabled && PrototypeCounter < countConfig) {
        Matcher ProtoPollutionRespMatch = ProtoPollutionPattern.matcher(respBody);
        
        // Create an issue if we match any of the indicators for prototype pollution sink
        if (ProtoPollutionRespMatch.find()) {
            List<int[]> ProtoPollutionMatches = getMatches(messageInfo.getResponse(), ProtoPollutionRespMatch.group(0).getBytes());
            reportIssue(messageInfo, null, ProtoPollutionMatches, "[IoV] Prototype Pollution Potential Sink", "The response contained the following text, indicating JavaScript variables might be merged/cloned/extended in an insecure manner: " + ProtoPollutionRespMatch.group(0) + ".<BR>See also:<BR>https://medium.com/node-modules/what-is-prototype-pollution-and-why-is-it-such-a-big-deal-2dd8d89a93c<BR>https://codeburst.io/what-is-prototype-pollution-49482fc4b638", "Information", "Tentative");
            PrototypeCounter++;
        }
      }
      
      if (isParsePatternEnabled && ParseCounter < countConfig) {
        Matcher ParseServerMatch = ParseServerPattern.matcher(reqRaw);
        
        // Create an issue if we match a request that includes Parse Server headers
        if (ParseServerMatch.find()) {
            List<int[]> ParseServerMatches = getMatches(messageInfo.getRequest(), ParseServerMatch.group(0).getBytes());
            reportIssue(messageInfo, ParseServerMatches, null, "[IoV] Parse Server Identified", "The response headers contained the following Parse Server application ID: " + ParseServerMatch.group(0), "Information", "Tentative");
            ParseCounter++;
        }
      }
      
      // Check Parameters for potential targets of attack
      for (IParameter parameter : requestInfo.getParameters()) {
        
        if (isFilePatternEnabled && FileCounter < countConfig) {
            Matcher FileParamMatch = FileHandlingPattern.matcher(parameter.getName());
            Matcher FileParamValueMatch = FileValuePattern.matcher(parameter.getValue());
            
            // Create an issue if we match any of the potential sources of attack for
            // SSTI/ SSRF / LFI / RFI / Directory Traversal / URL injection. These are areas to focus
            // these attacks, not confirmed vulnerabilities.
            if (FileParamMatch.find()) {
                List<int[]> FileParamMatches = getMatches(messageInfo.getRequest(), FileParamMatch.group(0).getBytes());
                reportIssue(messageInfo, FileParamMatches, null, "[IoV] Target for SSRF/SSTI/LFI/RFI/URLi/DirTraversal", "The request contained the following potential target parameter name: " + FileParamMatch.group(0), "Information", "Tentative");
                FileCounter++;
            }
        
            // Check for parameter values that might be vulnerable to SSRF / URL redirection / etc
            if (FileParamValueMatch.find()) {
                List<int[]> FileParamValueMatches = getMatches(messageInfo.getRequest(), FileParamValueMatch.group(0).getBytes());
                reportIssue(messageInfo, FileParamValueMatches, null, "[IoV] Target for SSRF/SSTI/LFI/RFI/URLi/DirTraversal", "The request contained the following potential target parameter value: " + FileParamValueMatch.group(0), "Information", "Tentative");
                FileCounter++;
            }
        }
        
        if (isCmdPatternEnabled && CmdCounter < countConfig) {
            Matcher CmdParamMatch = CmdPattern.matcher(parameter.getName());
            Matcher CmdParamValueMatch = CmdPattern.matcher(parameter.getValue());
            
            // Check for parameters indicative of being vulnerable to CMDi
            if (CmdParamMatch.find()) {
                List<int[]> CmdParamMatches = getMatches(messageInfo.getRequest(), CmdParamMatch.group(0).getBytes());
                reportIssue(messageInfo, CmdParamMatches, null, "[IoV] Target for CMDi", "The request contained the following potential target parameter name: " + CmdParamMatch.group(0), "Information", "Tentative");
                CmdCounter++;
            }
        
            // Check for parameters indicative of being vulnerable to CMDi
            if (CmdParamValueMatch.find()) {
                List<int[]> CmdParamMatches = getMatches(messageInfo.getRequest(), CmdParamValueMatch.group(0).getBytes());
                reportIssue(messageInfo, CmdParamMatches, null, "[IoV] Target for CMDi", "The request contained the following potential target parameter value: " + CmdParamValueMatch.group(0), "Information", "Tentative");
                CmdCounter++;
            }
        }
        
        if (isSuspiciousPatternEnabled && SuspiciousCounter < countConfig) {
            Matcher SuspiciousParamMatchName = SuspiciousPattern.matcher(parameter.getName());
            Matcher SuspiciousParamMatchValue = SuspiciousPattern.matcher(parameter.getValue());
            
            // Check for parameters that are suspicious
            if (SuspiciousParamMatchName.find()) {
                List<int[]> SuspiciousParamMatches = getMatches(messageInfo.getRequest(), SuspiciousParamMatchName.group(0).getBytes());
                reportIssue(messageInfo, SuspiciousParamMatches, null, "[IoV] Suspicious Parameters to Target", "The request contained the following potential target parameter name: " + SuspiciousParamMatchName.group(0), "Information", "Tentative");
                SuspiciousCounter++;
            }
        
            if (SuspiciousParamMatchValue.find()) {
                List<int[]> SuspiciousParamMatches = getMatches(messageInfo.getRequest(), SuspiciousParamMatchValue.group(0).getBytes());
                reportIssue(messageInfo, SuspiciousParamMatches, null, "[IoV] Suspicious Parameters to Target", "The request contained the following potential target parameter value: " + SuspiciousParamMatchValue.group(0), "Information", "Tentative");
                SuspiciousCounter++;
            }
        }
        
        if (isIdorPatternEnabled && IdorCounter < countConfig) {
            Matcher IdorParamMatch = IdorHandlingPattern.matcher(parameter.getName());
            
            // Check for parameters indicative of being vulnerable to IDOR
            if (IdorParamMatch.find()) {
                if (parameter.getValue().matches("^[0-9].*")) {
                    List<int[]> IdorParamMatches = getMatches(messageInfo.getRequest(), IdorParamMatch.group(0).getBytes());
                    reportIssue(messageInfo, IdorParamMatches, null, "[IoV] Target for IDOR", "The request contained the following potential target parameter: " + IdorParamMatch.group(0), "Information", "Tentative");
                    IdorCounter++;
                }
            }
        }
        
        if (isSqliParamPatternEnabled && SqliParamCounter < countConfig) {
            Matcher SqlParamMatch = SqlParamPattern.matcher(parameter.getName());
        
            // Check for parameters indicative of being vulnerable to SQLi
            if (SqlParamMatch.find()) {
                List<int[]> SqlParamMatches = getMatches(messageInfo.getRequest(), SqlParamMatch.group(0).getBytes());
                reportIssue(messageInfo, SqlParamMatches, null, "[IoV] Target for SQLi", "The request contained the following potential target parameter: " + SqlParamMatch.group(0), "Information", "Tentative");
                SqliParamCounter++;
            }
        }
      }
    }
      
    return null;
  }
  
  // Active scanning for prototype pollution
  @Override
  public List<IScanIssue> doActiveScan(IHttpRequestResponse messageInfo, IScannerInsertionPoint insertionPoint) {
    // Only process requests if the URL is in scope
    String checkUrl = extHelpers.analyzeRequest(messageInfo).getUrl().toString();
    if (extCallbacks.isInScope(extHelpers.analyzeRequest(messageInfo).getUrl()) && !checkUrl.endsWith(".jpg") && 
            !checkUrl.endsWith(".png") && !checkUrl.endsWith(".gif") && !checkUrl.endsWith(".ico") && 
            !checkUrl.endsWith(".css") && !checkUrl.endsWith(".mpg") && !checkUrl.endsWith(".mpeg") &&
            !checkUrl.endsWith(".mp4") && !checkUrl.endsWith(".woff") && !checkUrl.endsWith(".woff2") &&
            !checkUrl.endsWith(".jpeg")) {
        
      // Setup default request variables for URL and body
      String randVal = genRandStr();
      Pattern RandPattern = Pattern.compile(randVal);
      IRequestInfo requestInfo = extHelpers.analyzeRequest(messageInfo);
      String req = new String(messageInfo.getRequest());
      String reqBody = req.substring(extHelpers.analyzeResponse(messageInfo.getRequest()).getBodyOffset());
      
      if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON && isPrototypePatternEnabled && PrototypeCounter < countConfig) {
        try {
          JSONObject jsonAddToEnd = new JSONObject(reqBody);
          JSONObject jsonModify = new JSONObject(reqBody);
          String jsonAppendString = "{\"param-pollution-param-" + randVal + "\": \"param-pollution-val-" + randVal + "\"}";
          JSONObject jsonAppend = new JSONObject(jsonAppendString);
          jsonAddToEnd.put("__proto__", jsonAppend);

          byte[] appendReq = extHelpers.buildHttpMessage(requestInfo.getHeaders(), extHelpers.stringToBytes(jsonAddToEnd.toString()));

          // Send the updated parameter in a request
          IHttpRequestResponse appendReqResponse = extCallbacks.makeHttpRequest(messageInfo.getHttpService(), appendReq);
          String appendResp = new String(appendReqResponse.getResponse());
          Matcher RandPatternAppendMatch = RandPattern.matcher(appendResp);
          
          // If the random value was returned in the response, maybe vulnerable
          if (RandPatternAppendMatch.find()) {
            List<int[]> RandPatternAppendMatches = getMatches(appendReqResponse.getResponse(), RandPatternAppendMatch.group(0).getBytes());
            reportIssue(appendReqResponse, null, RandPatternAppendMatches, "[IoV] Potentially Vulnerable to Prototype Pollution", "The request contained the following potential target parameter: " + RandPatternAppendMatch.group(0) + ".<BR>See also:<BR>https://medium.com/node-modules/what-is-prototype-pollution-and-why-is-it-such-a-big-deal-2dd8d89a93c<BR>https://codeburst.io/what-is-prototype-pollution-49482fc4b638", "Low", "Tentative");
            PrototypeCounter++;
          }
          
          // Loop through JSON parameters to modify
          for (int i = 0; i < jsonModify.names().length(); i++) {
            JSONObject jsonModifyKeyValue1 = new JSONObject(reqBody);
            String jsonModifyString1 = "{\"" + jsonModify.names().getString(i) + "\": \"param-pollution1-" + randVal + "\"}";
            JSONObject jsonEdit1 = new JSONObject(jsonModifyString1);
            jsonModifyKeyValue1.remove(jsonModify.names().getString(i));
            jsonModifyKeyValue1.put("__proto__", jsonEdit1);
            
            byte[] modifyReq1 = extHelpers.buildHttpMessage(requestInfo.getHeaders(), extHelpers.stringToBytes(jsonModifyKeyValue1.toString()));

            // Send the updated parameter in a request
            IHttpRequestResponse modifyReqResponse1 = extCallbacks.makeHttpRequest(messageInfo.getHttpService(), modifyReq1);
            String modifyResp1 = new String(modifyReqResponse1.getResponse());
            Matcher RandPatternModifyMatch1 = RandPattern.matcher(modifyResp1);
          
            // If the random value was returned in the response, maybe vulnerable
            if (RandPatternModifyMatch1.find()) {
              List<int[]> RandPatternModifyMatches1 = getMatches(modifyReqResponse1.getResponse(), RandPatternModifyMatch1.group(0).getBytes());
              reportIssue(modifyReqResponse1, null, RandPatternModifyMatches1, "[IoV] Potentially Vulnerable to Prototype Pollution", "The request contained the following potential target parameter: " + RandPatternModifyMatch1.group(0) + ".<BR>See also:<BR>https://medium.com/node-modules/what-is-prototype-pollution-and-why-is-it-such-a-big-deal-2dd8d89a93c<BR>https://codeburst.io/what-is-prototype-pollution-49482fc4b638", "Low", "Tentative");
              PrototypeCounter++;
            }
            
            JSONObject jsonModifyKeyValue2 = new JSONObject(reqBody);
            String jsonModifyString2 = "{\"prototype\": {\"" + jsonModify.names().getString(i) + "\": \"param-pollution2-" + randVal + "\"} }";
            JSONObject jsonEdit2 = new JSONObject(jsonModifyString2);
            jsonModifyKeyValue2.remove(jsonModify.names().getString(i));
            jsonModifyKeyValue2.put("constructor", jsonEdit2);
            
            byte[] modifyReq2 = extHelpers.buildHttpMessage(requestInfo.getHeaders(), extHelpers.stringToBytes(jsonModifyKeyValue2.toString()));

            // Send the updated parameter in a request
            IHttpRequestResponse modifyReqResponse2 = extCallbacks.makeHttpRequest(messageInfo.getHttpService(), modifyReq2);
            String modifyResp2 = new String(modifyReqResponse2.getResponse());
            Matcher RandPatternModifyMatch2 = RandPattern.matcher(modifyResp2);
          
            // If the random value was returned in the response, maybe vulnerable
            if (RandPatternModifyMatch2.find()) {
              List<int[]> RandPatternModifyMatches2 = getMatches(modifyReqResponse2.getResponse(), RandPatternModifyMatch2.group(0).getBytes());
              reportIssue(modifyReqResponse2, null, RandPatternModifyMatches2, "[IoV] Potentially Vulnerable to Prototype Pollution", "The request contained the following potential target parameter: " + RandPatternModifyMatch2.group(0) + ".<BR>See also:<BR>https://medium.com/node-modules/what-is-prototype-pollution-and-why-is-it-such-a-big-deal-2dd8d89a93c<BR>https://codeburst.io/what-is-prototype-pollution-49482fc4b638", "Low", "Tentative");
              PrototypeCounter++;
            }
          }
        } catch (Exception ignore) { }
      }        
    }
    
    return null;
  }
  
  @Override
  public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
    // This method is called when multiple issues are reported for the same URL 
    // path by the same extension-provided check. The value we return from this 
    // method determines how/whether Burp consolidates the multiple issues
    // to prevent duplication
    //
    // Since the issue name is sufficient to identify our issues as different,
    // if both issues have the same name, only report the existing issue
    // otherwise report both issues
    if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
      return -1;
    else return 0;
  }
  
  // Process requests and responses and look for specified content
  @Override
  public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    // Only process requests if the URL is in scope
    String checkUrl = extHelpers.analyzeRequest(messageInfo).getUrl().toString();
    if (extCallbacks.isInScope(extHelpers.analyzeRequest(messageInfo).getUrl()) && !checkUrl.endsWith(".jpg") && 
            !checkUrl.endsWith(".png") && !checkUrl.endsWith(".gif") && !checkUrl.endsWith(".ico") && 
            !checkUrl.endsWith(".css") && !checkUrl.endsWith(".mpg") && !checkUrl.endsWith(".mpeg") &&
            !checkUrl.endsWith(".mp4") && !checkUrl.endsWith(".woff") && !checkUrl.endsWith(".woff2") &&
            !checkUrl.endsWith(".jpeg")) {
    
      // Process checks in the response
      if (!messageIsRequest) {
        // Setup default response body variable
        String respRaw = new String(messageInfo.getResponse());
        String respBody = respRaw.substring(extHelpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset());
      
        // Create patter matchers for each type
        
        if (isXxePatternEnabled && XxeCounter < countConfig) {
            Matcher XxeMatch = XxePattern.matcher(respBody);
            
            // Create an issue if we match any of the indicators for XXE vulnerabilities
            if (XxeMatch.find()) {
                List<int[]> XxeMatches = getMatches(messageInfo.getResponse(), XxeMatch.group(0).getBytes());
                reportIssue(messageInfo, null, XxeMatches, "[IoV] XXE Indicator of Vulnerability", "The response contained the following text: " + XxeMatch.group(0), "Low", "Tentative");
                XxeCounter++;
            }
        }
        
        if (isSqliDbPatternEnabled && SqliDbCounter < countConfig) {
            Matcher SqlMatch = SqlPattern.matcher(respBody);
            
            // Create an issue if we match any of the indicators for SQLi vulnerabilities
            if (SqlMatch.find()) {
                List<int[]> SqlMatches = getMatches(messageInfo.getResponse(), SqlMatch.group(0).getBytes());
                reportIssue(messageInfo, null, SqlMatches, "[IoV] SQLi Indicator of Vulnerability", "The response contained the following text: " + SqlMatch.group(0), "Low", "Tentative");
                SqliDbCounter++;
            }
        }
        
        if (isSerialPatternEnabled && SerialCounter < countConfig) {
            Matcher SerialMatch = SerialPattern.matcher(respBody);
            
            // Create an issue if we match any of the indicators for Deserialization vulnerabilities
            if (SerialMatch.find()) {
                List<int[]> SerialMatches = getMatches(messageInfo.getResponse(), SerialMatch.group(0).getBytes());
                reportIssue(messageInfo, null, SerialMatches, "[IoV] Serialization Indicator of Vulnerability", "The response contained the following text: " + SerialMatch.group(0), "Low", "Tentative");
                SerialCounter++;
            }
        }
        
        if (isSecretsPatternEnabled && SecretsCounter < countConfig) {
            Matcher SecretsMatch = SecretsPattern.matcher(respBody);
            
            // Create an issue if we match any potential secrets
            if (SecretsMatch.find()) {
                List<int[]> SecretsMatches = getMatches(messageInfo.getResponse(), SecretsMatch.group(0).getBytes());
                reportIssue(messageInfo, null, SecretsMatches, "[IoV] Leaked Secrets Indicator of Vulnerability", "The response contained the following text: " + SecretsMatch.group(0), "Medium", "Tentative");
                SecretsCounter++;
            }
        }
        
        if (isSubdomainPatternEnabled && SubdomainCounter < countConfig) {
            Matcher SubdomainTakeoverMatch = SubdomainTakeoverPattern.matcher(respBody);
      
            // Create an issue noting the response indicates the potential for subdomain takeover
            if (SubdomainTakeoverMatch.find()) {
                List<int[]> SubdomainTakeoverMatches = getMatches(messageInfo.getResponse(), SubdomainTakeoverMatch.group(0).getBytes());
                reportIssue(messageInfo, null, SubdomainTakeoverMatches, "[IoV] Subdomain Takeover Potential", "The response body contained a string that indicates vulnerability to subdomain takeovers: " + SubdomainTakeoverMatch.group(0) + "<BR>See also: https://github.com/EdOverflow/can-i-take-over-xyz", "High", "Firm");
                SubdomainCounter++;
            }
        }
      }
    }
  }
  
  // helper method to search a response for occurrences of a literal match string
  // and return a list of start/end offsets
  private List<int[]> getMatches(byte[] response, byte[] match) {
    List<int[]> matches = new ArrayList<int[]>();

    int start = 0;
    while (start < response.length) {
      start = extHelpers.indexOf(response, match, true, start, response.length);
      if (start == -1)
        break;
      matches.add(new int[] { start, start + match.length });
      start += match.length;
    }

    return matches;
  }
  
  // Create issues from the reported findings
  private IScanIssue reportIssue(IHttpRequestResponse baseRequestResponse, List<int[]>reqMatches, List<int[]>respMatches, String IssueName, String IssueMatch, String Severity, String Confidence) {
      IScanIssue issue = new CustomScanIssue(
          baseRequestResponse.getHttpService(),
          extHelpers.analyzeRequest(baseRequestResponse).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(baseRequestResponse, reqMatches, respMatches) }, 
          IssueName,
          IssueMatch,
          Severity,
          Confidence
      );

      String issueUrl = extHelpers.analyzeRequest(baseRequestResponse).getUrl().getProtocol() + "://" + extHelpers.analyzeRequest(baseRequestResponse).getUrl().getHost() + extHelpers.analyzeRequest(baseRequestResponse).getUrl().getPath();
      IScanIssue issues[] = extCallbacks.getScanIssues(issueUrl);
      int ReportMatch = 0;

      if (issues.length >= 1) {
        for (int i=0; i<issues.length;i++) { 
          if (issues[i].getIssueName().equals(IssueName)) {
            ReportMatch = 1;
          }
        }
        
        if (ReportMatch == 0) {
          extCallbacks.addScanIssue(issue);
        }
      } else {
        extCallbacks.addScanIssue(issue);
      }

      return issue;
  }
}

class CustomScanIssue implements IScanIssue {
  private IHttpService httpService;
  private URL url;
  private IHttpRequestResponse[] httpMessages;
  private String name;
  private String detail;
  private String severity;
  private String confidence;

  public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity, String confidence) {
    this.httpService = httpService;
    this.url = url;
    this.httpMessages = httpMessages;
    this.name = name;
    this.detail = detail;
    this.severity = severity;
    this.confidence = confidence;
  }
    
  @Override
  public URL getUrl() {
    return url;
  }

  @Override
  public String getIssueName() {
    return name;
  }

  @Override
  public int getIssueType() {
    return 0;
  }

  @Override
  public String getSeverity() {
    return severity;
  }

  @Override
  public String getConfidence() {
    return confidence;
  }

  @Override
  public String getIssueBackground() {
    return null;
  }

  @Override
  public String getRemediationBackground() {
    return null;
  }

  @Override
  public String getIssueDetail() {
    return detail;
  }

  @Override
  public String getRemediationDetail() {
    return null;
  }

  @Override
  public IHttpRequestResponse[] getHttpMessages() {
    return httpMessages;
  }

  @Override
  public IHttpService getHttpService() {
    return httpService;
  }
}