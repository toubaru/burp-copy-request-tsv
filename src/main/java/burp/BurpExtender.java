package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	private static final String EMPTY           = "";
	private static final String FillBlank       = "-";
	private static final String Scheme          = "://";
	private static final String Quot            = "\"";
	private static final String EscapeQuot      = "\"\"";
	private static final String Separator       = "\t";
	private static final String NewLine         = System.getProperty("line.separator");
	private static final String FirstKey        = "jsonData";
	private static final String BinaryString    = "(Binary)";
	private static final String NullString      = "(Null)";
	private static final String ArrayIndexStart = "[";
	private static final String ArrayIndexEnd   = "]";
	private static final String EncodeCharset   = "iso8859-1";
	private static final String SplitHeader     = ": ";
	private static final String SplitUrlPath    = "/";
	private static final String[] SkipHeaders   = {"Cookie:"};
	private static final String TypePath        = "Path";
	private static final String TypeHeader      = "Header";
	private static final String TypeBody        = "Body";
	private static final String TypeUrl         = "URL";
	private static final String TypeCookie      = "Cookie";
	private static final String TypeUnknown     = "UnknownType:";
	private static final String Title           = "Copy Request Tsv";
	private static final String MenuItemName1   = "Copy Request Tsv (Full)";
	private static final String MenuItemName2   = "Copy Request Tsv (Header)";
	private static final String MenuItemName3   = "Copy Request Tsv (Get/POST/Cookie)";
	private static final String MenuItemName4   = "Copy Request Tsv (Json)";
	private static enum TsvColumns {URL,METHOD,TYPE,NAME,VALUE};

	private static final Pattern patternControlCharacter = Pattern.compile("[\\x00-\\x1F\\x7F]");
	private static final Pattern patternQuot = Pattern.compile(Quot);
	private static final CharsetDecoder decoder = Charset.defaultCharset().newDecoder();
	private static JsonParser jp;

	private IBurpExtenderCallbacks callbacks;
	private final List menuList = new ArrayList<>();
	private IExtensionHelpers helpers;
	
	//
	// implement IBurpExtender
	//
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers   = callbacks.getHelpers();
		this.jp        = new JsonParser();
		callbacks.setExtensionName(Title);
		callbacks.registerContextMenuFactory(this);
	}
	
	//
	// implement IContextMenuFactory
	//
	
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IContextMenuInvocation contextMenuInvocation = invocation;
		
     	menuList.clear();
		
		if(contextMenuInvocation.getSelectedMessages()  == null) {
			return menuList;
		}
		
		JMenuItem menuItem1 = new JMenuItem();
		menuItem1.setText(MenuItemName1);
		menuItem1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] messageList = contextMenuInvocation.getSelectedMessages();
				StringBuilder sb = new StringBuilder();
				
				if(messageList == null) {
					return;
				}
				
				for(IHttpRequestResponse message:messageList) {
					if(message.getRequest().length > 0) {
						
						// メソッド + URL + Path + ヘッダ を取得
						sb.append(cnvertList2Tsv(getHeader(message)));
						
						// get + post + cookie パラメータを取得
						sb.append(cnvertList2Tsv(getParams(message)));
						
						// json パラメータを取得
						sb.append(cnvertList2Tsv(getJson(message)));
					}
				}
				
				// clipboard
				Toolkit toolkit = Toolkit.getDefaultToolkit();
				Clipboard clipboard = toolkit.getSystemClipboard();
				StringSelection selection = new StringSelection(sb.toString());
				clipboard.setContents(selection, selection);
			}
		});
		menuList.add(menuItem1);
		
		JMenuItem menuItem2 = new JMenuItem();
		menuItem2.setText(MenuItemName2);
		menuItem2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] messageList = contextMenuInvocation.getSelectedMessages();
				StringBuilder sb = new StringBuilder();
				
				if(messageList == null) {
					return;
				}
				
				for(IHttpRequestResponse message:messageList) {
					if(message.getRequest().length > 0) {
						// メソッド + URL + ヘッダ を取得
						sb.append(cnvertList2Tsv(getHeader(message)));
					}
				}
				
				// clipboard
				Toolkit toolkit = Toolkit.getDefaultToolkit();
				Clipboard clipboard = toolkit.getSystemClipboard();
				StringSelection selection = new StringSelection(sb.toString());
				clipboard.setContents(selection, selection);
			}
		});
		menuList.add(menuItem2);
		
		JMenuItem menuItem3 = new JMenuItem();
		menuItem3.setText(MenuItemName3);
		menuItem3.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] messageList = contextMenuInvocation.getSelectedMessages();
				StringBuilder sb = new StringBuilder();
				
				if(messageList == null) {
					return;
				}
				
				for(IHttpRequestResponse message:messageList) {
					if(message.getRequest().length > 0) {
						// get + post + cookie パラメータを取得
						sb.append(cnvertList2Tsv(getParams(message)));
					}
				}
				
				// clipboard
				Toolkit toolkit = Toolkit.getDefaultToolkit();
				Clipboard clipboard = toolkit.getSystemClipboard();
				StringSelection selection = new StringSelection(sb.toString());
				clipboard.setContents(selection, selection);
			}
		});
		menuList.add(menuItem3);
		
		JMenuItem menuItem4 = new JMenuItem();
		menuItem4.setText(MenuItemName4);
		menuItem4.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] messageList = contextMenuInvocation.getSelectedMessages();
				StringBuilder sb = new StringBuilder();
				
				if(messageList == null) {
					return;
				}
				
				for(IHttpRequestResponse message:messageList) {
					if(message.getRequest().length > 0) {
						// json パラメータを取得
						sb.append(cnvertList2Tsv(getJson(message)));
					}
				}
				
				// clipboard
				Toolkit toolkit = Toolkit.getDefaultToolkit();
				Clipboard clipboard = toolkit.getSystemClipboard();
				StringSelection selection = new StringSelection(sb.toString());
				clipboard.setContents(selection, selection);
			}
		});
		menuList.add(menuItem4);
		
        return menuList;
	}
	
	public String decode(String value) {
		String s;
		if(value == null) {
			s = NullString;
		} else {
			try {
				// 日本語文字化け対応
				s = decoder.decode(ByteBuffer.wrap(value.getBytes(EncodeCharset))).toString();
			} catch (CharacterCodingException | UnsupportedEncodingException ex) {
				s = BinaryString;
			}
		}
		return s;
	}
	
	public String convertTsvOutData(String value) {
		String result;
		// 制御文字の除去
		result = patternControlCharacter.matcher(value).replaceAll(EMPTY);
		// ダブルクォートのエスケープ
		result = patternQuot.matcher(result).replaceAll(EscapeQuot);
		return result;
	}
	
	public List<Map<Integer, String>> addTsvList(List<Map<Integer, String>> orgData,List<Map<Integer, String>> addData) {
		List<Map<Integer, String>> result = orgData;
		if(addData == null) return result;
		for(Map<Integer, String> map:addData) {
			result.add(map);
		}
		return result;
	}

	public String cnvertList2Tsv(List<Map<Integer, String>> tsvDataList) {
		StringBuilder sb = new StringBuilder();
		if(tsvDataList == null) return sb.toString();
		for(Map<Integer, String> map:tsvDataList) {
			sb.append(Quot);
			sb.append(convertTsvOutData(map.get(TsvColumns.METHOD.ordinal())));
			sb.append(Quot);
			sb.append(Separator);
			sb.append(Quot);
			sb.append(convertTsvOutData(map.get(TsvColumns.URL.ordinal())));
			sb.append(Quot);
			sb.append(Separator);
			sb.append(Quot);
			sb.append(convertTsvOutData(map.get(TsvColumns.TYPE.ordinal())));
			sb.append(Quot);
			sb.append(Separator);
			sb.append(Quot);
			sb.append(convertTsvOutData(map.get(TsvColumns.NAME.ordinal())));
			sb.append(Quot);
			sb.append(Separator);
			sb.append(Quot);
			sb.append(convertTsvOutData(map.get(TsvColumns.VALUE.ordinal())));
			sb.append(Quot);
			sb.append(NewLine);
		}
		return sb.toString();
	}
	
	public Map<Integer, String> makeTsvList(String method,String url,String type,String name,String value) {
		Map<Integer, String> map = new HashMap<>();
		map.put(TsvColumns.METHOD.ordinal(), method);
		map.put(TsvColumns.URL.ordinal(),    url);
		map.put(TsvColumns.TYPE.ordinal(),   type);
		map.put(TsvColumns.NAME.ordinal(),   name);
		map.put(TsvColumns.VALUE.ordinal(),  value);
		return map;
	}
	
	public List<Map<Integer, String>> getHeader(IHttpRequestResponse message) {
		List<Map<Integer, String>> result = new ArrayList<>();
		IRequestInfo requestInfo = helpers.analyzeRequest(message.getHttpService(),message.getRequest());
		
		// Method + URL
		URL url = requestInfo.getUrl();
		StringBuilder sbUrl = new StringBuilder();
		sbUrl.append(url.getProtocol()).append(Scheme).append(url.getHost()).append(url.getPath());
		result.add(makeTsvList(requestInfo.getMethod(),sbUrl.toString(),FillBlank,FillBlank,FillBlank));
		
		// path
		String[] paths = url.getPath().split(SplitUrlPath);
		int pathIndex=0;
		for(String path:paths) {
			if(pathIndex == 0) {
				pathIndex++;
				continue;
			}
			result.add(makeTsvList(EMPTY,EMPTY,TypePath,Integer.toString(pathIndex++),path));
		}
		
		// header
		List<String> headers = requestInfo.getHeaders();
		boolean isFirst = true;
		for(String header:headers) {
			// スキップ対象のヘッダはコピー対象外にする
			boolean isSkip = false;
			for(String skip:SkipHeaders) {
				if(header.startsWith(skip)) {
					isSkip = true;
					break;
				}
			}
			if(isSkip) continue;
			
			if(!isFirst) {
				String[] splitHeaders = header.split(SplitHeader, 0);
				String key,value;
				if(splitHeaders.length == 2) {
					key   = splitHeaders[0];
					value = splitHeaders[1];
				} else {
					key   = header;
					value = EMPTY;
				}
				result.add(makeTsvList(EMPTY,EMPTY,TypeHeader,key,value));
			} else {
				isFirst = false;
			}
		}
		return result;
	}

	public List<Map<Integer, String>> getParams(IHttpRequestResponse message) {
		List<Map<Integer, String>> result = new ArrayList<>();
		StringBuilder sb = new StringBuilder();
		IRequestInfo requestInfo = helpers.analyzeRequest(message.getHttpService(),message.getRequest());
		List<IParameter> iParameters = requestInfo.getParameters();
		for(IParameter iParameter:iParameters) {
			Map<Integer, String> map = new HashMap<>();
			switch (iParameter.getType()) {
				case IParameter.PARAM_URL:
					result.add(makeTsvList(EMPTY,EMPTY,TypeUrl,iParameter.getName(),decode(iParameter.getValue())));
					break;
				case IParameter.PARAM_COOKIE:
					result.add(makeTsvList(EMPTY,EMPTY,TypeCookie,iParameter.getName(),decode(iParameter.getValue())));
					break;
				case IParameter.PARAM_BODY:
				case IParameter.PARAM_MULTIPART_ATTR:
				case IParameter.PARAM_XML:
				case IParameter.PARAM_XML_ATTR:
					result.add(makeTsvList(EMPTY,EMPTY,TypeBody,iParameter.getName(),decode(iParameter.getValue())));
					break;
				case IParameter.PARAM_JSON:
					// SKIP
					break;
				default:
					// OTHER
					result.add(makeTsvList(EMPTY,EMPTY,TypeUnknown,iParameter.getName(),decode(iParameter.getValue())));
					break;
			}
		}
		return result;
	}

	public List<Map<Integer, String>> getJson(IHttpRequestResponse message) {
		if(IRequestInfo.CONTENT_TYPE_JSON == helpers.analyzeRequest(message.getRequest()).getContentType()) {
			int offset = helpers.analyzeRequest(message.getRequest()).getBodyOffset();
			String msg = new String(message.getRequest(), offset, message.getRequest().length-offset);
			return parseJson(msg);
		}
		return null;
	}

	public List<Map<Integer, String>> parseJson(String json) {
		return parseJson(json, FirstKey);
	}

	public List<Map<Integer, String>> parseJson(String json, String parentKey) {
		List<Map<Integer, String>> result = new ArrayList<>();
		StringBuilder sb = new StringBuilder();
		JsonElement je = jp.parse(json);
		if(je.isJsonObject()) {
			Set<Map.Entry<String, JsonElement>> entrySet = je.getAsJsonObject().entrySet();
			Iterator<Map.Entry<String, JsonElement>> it = entrySet.iterator();
			while(it.hasNext()) {
				Map.Entry<String, JsonElement> entry = it.next();
				StringBuilder key = new StringBuilder();
				key.append(parentKey).append(ArrayIndexStart).append(entry.getKey()).append(ArrayIndexEnd);
				if(entry.getValue().isJsonNull()) {
					result.add(makeTsvList(EMPTY,EMPTY,TypeBody,key.toString(),decode(null)));
				} else if(entry.getValue().isJsonObject()) {
					result = addTsvList(result,parseJson(entry.getValue().toString(),key.toString()));
				} else if(entry.getValue().isJsonArray()) {
					result = addTsvList(result,parseJson(entry.getValue().toString(),key.toString()));
				} else {
					result.add(makeTsvList(EMPTY,EMPTY,TypeBody,key.toString(),decode(entry.getValue().getAsString())));
				}
			}
		} else if(je.isJsonArray()) {
			int i=0;
			for(JsonElement jea : je.getAsJsonArray()) {
				StringBuilder key = new StringBuilder();
				key.append(parentKey).append(ArrayIndexStart).append(String.valueOf(i++)).append(ArrayIndexEnd);
				if(jea.isJsonNull()) {
					result.add(makeTsvList(EMPTY,EMPTY,TypeBody,key.toString(),decode(null)));
				} else if(jea.isJsonObject()) {
					result = addTsvList(result,parseJson(jea.getAsJsonObject().toString(), key.toString()));
				} else if(jea.isJsonArray()) {
					result = addTsvList(result,parseJson(jea.getAsJsonArray().toString(), key.toString()));
				} else {
					result.add(makeTsvList(EMPTY,EMPTY,TypeBody,key.toString(),decode(jea.getAsString())));
				}
			}
		}
		return result;
	}
	
}