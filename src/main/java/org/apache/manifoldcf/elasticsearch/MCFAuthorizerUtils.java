/* $Id: MCFAuthorizer.java 1571011 2014-02-23 13:46:13Z kwright $ */
/* Modified to MCFAuthorizerUtils.java 2015-04-28 Bart Superson */
/**
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements. See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.apache.manifoldcf.elasticsearch;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.ElasticsearchIllegalArgumentException;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.support.QuerySourceBuilder;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.index.query.*;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.search.RestSearchAction;
import org.elasticsearch.rest.action.support.RestActions;
import org.elasticsearch.search.Scroll;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.fetch.source.FetchSourceContext;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.search.sort.SortOrder;
import org.elasticsearch.index.query.QueryStringQueryBuilder.Operator;

import java.io.*;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.common.unit.TimeValue.parseTimeValue;
import static org.elasticsearch.search.suggest.SuggestBuilders.termSuggestion;


public class MCFAuthorizerUtils {

  protected static String ALLOW_FIELD_PREFIX = "allow_token_";
  protected static String DENY_FIELD_PREFIX = "deny_token_";

  protected final static String AUTHORITY_BASE_URL = "http://localhost:8345/mcf-authority-service";
  protected final static String FIELD_ALLOW_DOCUMENT = ALLOW_FIELD_PREFIX +"document";
  protected final static String FIELD_DENY_DOCUMENT = DENY_FIELD_PREFIX +"document";
  protected final static String FIELD_ALLOW_PARENT = ALLOW_FIELD_PREFIX +"share";
  protected final static String FIELD_DENY_PARENT = DENY_FIELD_PREFIX +"share";
  protected final static String FIELD_ALLOW_SHARE = ALLOW_FIELD_PREFIX +"parent";
  protected final static String FIELD_DENY_SHARE = DENY_FIELD_PREFIX +"parent";

  /** Special token for null security fields */
  protected static final String NOSECURITY_TOKEN = "__nosecurity__";

  private final static CloseableHttpClient httpClient = HttpClients.createDefault();

  private static final ESLogger log = Loggers.getLogger("MCFAuthorizer");

  public static SearchRequest parseSearchRequestMCF(RestRequest request) throws MCFAuthorizerException {
    SearchRequest searchRequest;
    String username = request.param("u");
    //if(username==null) throw new MCFAuthorizerException("Username not passed.");
    if(username!=null) {
      String[] indices = Strings.splitStringByCommaToArray(request.param("index"));
      searchRequest = new SearchRequest(indices);
      boolean isTemplateRequest = request.path().endsWith("/template");
      if(request.hasContent() || request.hasParam("source")) {
        FilterBuilder authorizationFilter = buildAuthorizationFilter(username);
        FilteredQueryBuilder filteredQueryBuilder;

        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode modifiedJSON, innerJSON;
        JsonNode requestJSON;

        try {
          requestJSON = objectMapper.readTree(RestActions.getRestContent(request).toBytes());
          if (isTemplateRequest) {
            modifiedJSON = (ObjectNode) requestJSON;
            innerJSON = (ObjectNode)requestJSON.findValue("template");
            filteredQueryBuilder = QueryBuilders.filteredQuery(QueryBuilders.wrapperQuery(innerJSON.findValue("query").toString()), authorizationFilter);
            modifiedJSON.replace("template",innerJSON.set("query", objectMapper.readTree(filteredQueryBuilder.buildAsBytes().toBytes())));
            searchRequest.templateSource(modifiedJSON.toString());
          } else {
            filteredQueryBuilder = QueryBuilders.filteredQuery(QueryBuilders.wrapperQuery(requestJSON.findValue("query").toString()), authorizationFilter);
            modifiedJSON = (ObjectNode) requestJSON;
            modifiedJSON.set("query", objectMapper.readTree(filteredQueryBuilder.buildAsBytes().toBytes()));
            searchRequest.source(modifiedJSON.toString());
          }
        } catch (IOException e) {
            e.printStackTrace();
            throw new MCFAuthorizerException("JSON parser error");
          }
      }

      searchRequest.extraSource(parseSearchSourceMCF(request));
      searchRequest.searchType(request.param("search_type"));
      searchRequest.queryCache(request.paramAsBoolean("query_cache", null));

      String scroll = request.param("scroll");
      if(scroll != null) {
        searchRequest.scroll(new Scroll(parseTimeValue(scroll,null)));
      }

      searchRequest.types(Strings.splitStringByCommaToArray(request.param("type")));
      searchRequest.routing(request.param("routing"));
      searchRequest.preference(request.param("preference"));
      searchRequest.indicesOptions(IndicesOptions.fromRequest(request, searchRequest.indicesOptions()));
    }
    else {
      searchRequest = RestSearchAction.parseSearchRequest(request);
    }
    return searchRequest;
  }

  public static SearchSourceBuilder parseSearchSourceMCF(RestRequest request) throws MCFAuthorizerException {
    SearchSourceBuilder searchSourceBuilder = null;
    QuerySourceBuilder querySourceBuilder = parseQuerySource(request);
    if (querySourceBuilder != null) {
      searchSourceBuilder = new SearchSourceBuilder();
      searchSourceBuilder.query(querySourceBuilder);
    }

    int from = request.paramAsInt("from", -1);
    if(from != -1) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.from(from);
    }

    int size = request.paramAsInt("size", -1);
    if(size != -1) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.size(size);
    }

    if(request.hasParam("explain")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.explain(request.paramAsBoolean("explain", null));
    }

    if(request.hasParam("version")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.version(request.paramAsBoolean("version", null));
    }

    if(request.hasParam("timeout")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.timeout(request.paramAsTime("timeout", null));
    }

    if(request.hasParam("terminate_after")) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      int terminateAfter = request.paramAsInt("terminate_after",
              SearchContext.DEFAULT_TERMINATE_AFTER);
      if(terminateAfter < 0) {
        throw new ElasticsearchIllegalArgumentException("terminateAfter must be > 0");
      }else if(terminateAfter > 0) {
        searchSourceBuilder.terminateAfter(terminateAfter);
      }
    }

    String sField = request.param("fields");
    if(sField != null) {
      if(searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      if(!Strings.hasText(sField)) {
        searchSourceBuilder.noFields();
      } else {
        String[] sFields = Strings.splitStringByCommaToArray(sField);
        if (sFields != null) {
          for (String field : sFields) {
            searchSourceBuilder.field(field);
          }
        }
      }
    }

    String sFieldDataFields = request.param("fielddata_fields");
    if (sFieldDataFields != null) {
      if (searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      if (Strings.hasText(sFieldDataFields)) {
        String[] sFields = Strings.splitStringByCommaToArray(sFieldDataFields);
        if (sFields != null) {
          for (String field : sFields) {
            searchSourceBuilder.fieldDataField(field);
          }
        }
      }
    }
    FetchSourceContext fetchSourceContext = FetchSourceContext.parseFromRestRequest(request);
    if (fetchSourceContext != null) {
      if (searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.fetchSource(fetchSourceContext);
    }

    if (request.hasParam("track_scores")) {
      if (searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.trackScores(request.paramAsBoolean("track_scores", false));
    }

    String sSorts = request.param("sort");
    if (sSorts != null) {
      if (searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      String[] sorts = Strings.splitStringByCommaToArray(sSorts);
      for (String sort : sorts) {
        int delimiter = sort.lastIndexOf(":");
        if (delimiter != -1) {
          String sortField = sort.substring(0, delimiter);
          String reverse = sort.substring(delimiter + 1);
          if ("asc".equals(reverse)) {
            searchSourceBuilder.sort(sortField, SortOrder.ASC);
          } else if ("desc".equals(reverse)) {
            searchSourceBuilder.sort(sortField, SortOrder.DESC);
          }
        } else {
          searchSourceBuilder.sort(sort);
        }
      }
    }

    String sStats = request.param("stats");
    if (sStats != null) {
      if (searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      searchSourceBuilder.stats(Strings.splitStringByCommaToArray(sStats));
    }

    String suggestField = request.param("suggest_field");
    if (suggestField != null) {
      String suggestText = request.param("suggest_text", request.param("q"));
      int suggestSize = request.paramAsInt("suggest_size", 5);
      if (searchSourceBuilder == null) {
        searchSourceBuilder = new SearchSourceBuilder();
      }
      String suggestMode = request.param("suggest_mode");
      searchSourceBuilder.suggest().addSuggestion(
              termSuggestion(suggestField).field(suggestField).text(suggestText).size(suggestSize)
                      .suggestMode(suggestMode)
      );
    }

    return searchSourceBuilder;
  }

  public static QuerySourceBuilder parseQuerySource(RestRequest request) {
    String queryString = request.param("q");
    if(queryString == null) {
      return null;
    } else {
      FilterBuilder authorizationFilter = buildAuthorizationFilter(request.param("u"));
      QueryStringQueryBuilder queryBuilder = QueryBuilders.queryStringQuery(queryString);
      queryBuilder.defaultField(request.param("df"));
      queryBuilder.analyzer(request.param("analyzer"));
      queryBuilder.analyzeWildcard(request.paramAsBoolean("analyze_wildcard", false));
      queryBuilder.lowercaseExpandedTerms(request.paramAsBoolean("lowercase_expanded_terms", true));
      queryBuilder.lenient(request.paramAsBoolean("lenient", null));
      String defaultOperator = request.param("default_operator");
      if(defaultOperator != null) {
        if("OR".equals(defaultOperator)) {
          queryBuilder.defaultOperator(Operator.OR);
        } else {
          if(!"AND".equals(defaultOperator)) {
            throw new ElasticsearchIllegalArgumentException("Unsupported defaultOperator [" + defaultOperator + "], can either be [OR] or [AND]");
          }

          queryBuilder.defaultOperator(Operator.AND);
        }
      }

      return (new QuerySourceBuilder()).setQuery(QueryBuilders.filteredQuery(queryBuilder, authorizationFilter));
    }
  }

  /** Main method for building a filter representing appropriate security.
   *@param domainMap is a map from MCF authorization domain name to user name,
   * and describes a complete user identity.
   *@return the filter builder.
   */
  public static FilterBuilder buildAuthorizationFilter(Map<String,String> domainMap)
          throws MCFAuthorizerException
  {
    if (AUTHORITY_BASE_URL == null)
      throw new IllegalStateException("Authority base URL required for finding access tokens for a user");

    if (domainMap == null || domainMap.size() == 0)
      throw new IllegalArgumentException("Cannot find user tokens for null user");

    StringBuilder sb = new StringBuilder("[");
    boolean first = true;
    for (String domain : domainMap.keySet())
    {
      if (!first)
        sb.append(",");
      else
        first = false;
      sb.append(domain).append(":").append(domainMap.get(domain));
    }
    sb.append("]");
    log.info("Trying to match docs for user '"+sb.toString()+"'");

    return buildAuthorizationFilter(getAccessTokens(domainMap));
  }

  /** Main method for building a filter representing appropriate security.
   *@param authenticatedUserName is a user name in the form "user@domain".
   *@return the filter builder.
   */
  public static FilterBuilder buildAuthorizationFilter(String authenticatedUserName)
          throws MCFAuthorizerException
  {
    return buildAuthorizationFilter(authenticatedUserName, "");
  }

  /** Main method for building a filter representing appropriate security.
   *@param authenticatedUserName is a user name in the form "user@domain".
   *@param authenticatedUserDomain is the corresponding MCF authorization domain.
   *@return the filter builder.
   */
  public static FilterBuilder buildAuthorizationFilter(String authenticatedUserName, String authenticatedUserDomain)
          throws MCFAuthorizerException
  {
    Map<String,String> domainMap = new HashMap<String,String>();
    domainMap.put(authenticatedUserDomain, authenticatedUserName);
    return buildAuthorizationFilter(domainMap);
  }

  /** Main method for building a filter representing appropriate security.
   *@param userAccessTokens are a set of tokens to use to construct the filter (presumably from mod_authz_annotate, upstream)
   *@return the wrapped query enforcing ManifoldCF security.
   */
  public static FilterBuilder buildAuthorizationFilter(List<String> userAccessTokens)
          throws MCFAuthorizerException
  {
    BoolFilterBuilder bq = new BoolFilterBuilder();

    FilterBuilder allowShareOpen = new TermFilterBuilder(FIELD_ALLOW_SHARE,NOSECURITY_TOKEN);
    FilterBuilder denyShareOpen = new TermFilterBuilder(FIELD_DENY_SHARE,NOSECURITY_TOKEN);
    FilterBuilder allowParentOpen = new TermFilterBuilder(FIELD_ALLOW_PARENT,NOSECURITY_TOKEN);
    FilterBuilder denyParentOpen = new TermFilterBuilder(FIELD_DENY_PARENT,NOSECURITY_TOKEN);
    FilterBuilder allowDocumentOpen = new TermFilterBuilder(FIELD_ALLOW_DOCUMENT,NOSECURITY_TOKEN);
    FilterBuilder denyDocumentOpen = new TermFilterBuilder(FIELD_DENY_DOCUMENT,NOSECURITY_TOKEN);

    if (userAccessTokens == null || userAccessTokens.size() == 0)
    {
      // Only open documents can be included.
      // That query is:
      // (FIELD_ALLOW_SHARE is empty AND FIELD_DENY_SHARE is empty AND FIELD_ALLOW_DOCUMENT is empty AND FIELD_DENY_DOCUMENT is empty)
      // We're trying to map to:  -(FIELD_ALLOW_SHARE:*) , which should be pretty efficient in Solr because it is negated.  If this turns out not to be so, then we should
      // have the SolrConnector inject a special token into these fields when they otherwise would be empty, and we can trivially match on that token.
      bq.must(allowShareOpen);
      bq.must(denyShareOpen);
      bq.must(allowParentOpen);
      bq.must(denyParentOpen);
      bq.must(allowDocumentOpen);
      bq.must(denyDocumentOpen);
    }
    else
    {
      // Extend the query appropriately for each user access token.
      bq.must(calculateCompleteSubquery(FIELD_ALLOW_SHARE, FIELD_DENY_SHARE,allowShareOpen,denyShareOpen,userAccessTokens));
      bq.must(calculateCompleteSubquery(FIELD_ALLOW_DOCUMENT, FIELD_DENY_DOCUMENT,allowDocumentOpen,denyDocumentOpen,userAccessTokens));
      bq.must(calculateCompleteSubquery(FIELD_ALLOW_PARENT, FIELD_DENY_PARENT,allowParentOpen,denyParentOpen,userAccessTokens));
    }

    return bq;
  }

  /** Calculate a complete subclause, representing something like:
   * ((FIELD_ALLOW_SHARE is empty AND FIELD_DENY_SHARE is empty) OR FIELD_ALLOW_SHARE HAS token1 OR FIELD_ALLOW_SHARE HAS token2 ...)
   *     AND FIELD_DENY_SHARE DOESN'T_HAVE token1 AND FIELD_DENY_SHARE DOESN'T_HAVE token2 ...
   */
  private static FilterBuilder calculateCompleteSubquery(String allowField, String denyField, FilterBuilder allowOpen, FilterBuilder denyOpen, List<String> userAccessTokens)
  {
    BoolFilterBuilder bq = new BoolFilterBuilder();
    // No ES equivalent - hope this is done right inside
    //bq.setMaxClauseCount(1000000);

    // Add the empty-acl case
    BoolFilterBuilder subUnprotectedClause = new BoolFilterBuilder();
    subUnprotectedClause.must(allowOpen);
    subUnprotectedClause.must(denyOpen);
    bq.should(subUnprotectedClause);
    for (String accessToken : userAccessTokens)
    {
      bq.should(new TermFilterBuilder(allowField,accessToken));
      bq.mustNot(new TermFilterBuilder(denyField,accessToken));
    }
    return bq;
  }

  /** Get access tokens given a username */
  protected static List<String> getAccessTokens(Map<String,String> domainMap)
          throws MCFAuthorizerException
  {
    try
    {
      StringBuilder urlBuffer = new StringBuilder(AUTHORITY_BASE_URL);
      urlBuffer.append("/UserACLs");
      int i = 0;
      for (String domain : domainMap.keySet())
      {
        if (i == 0)
          urlBuffer.append("?");
        else
          urlBuffer.append("&");
        // For backwards compatibility, handle the singleton case specially
        if (domainMap.size() == 1 && domain.length() == 0)
        {
          urlBuffer.append("username=").append(URLEncoder.encode(domainMap.get(domain),"utf-8"));
        }
        else
        {
          urlBuffer.append("username_").append(Integer.toString(i)).append("=").append(URLEncoder.encode(domainMap.get(domain),"utf-8")).append("&")
                  .append("domain_").append(Integer.toString(i)).append("=").append(URLEncoder.encode(domain,"utf-8"));
        }
        i++;
      }
      String theURL = urlBuffer.toString();
      HttpGet method = new HttpGet(theURL);
      try
      {
        HttpResponse httpResponse = httpClient.execute(method);
        int rval = httpResponse.getStatusLine().getStatusCode();
        if (rval != 200)
        {
          String response = EntityUtils.toString(httpResponse.getEntity(),"utf-8");
          throw new MCFAuthorizerException("Couldn't fetch user's access tokens from ManifoldCF authority service: "+Integer.toString(rval)+"; "+response);
        }
        InputStream is = httpResponse.getEntity().getContent();
        try
        {
          String charSet = ContentType.getOrDefault(httpResponse.getEntity()).getCharset().toString();
          if (charSet == null)
            charSet = "utf-8";
          Reader r = new InputStreamReader(is,charSet);
          try
          {
            BufferedReader br = new BufferedReader(r);
            try
            {
              // Read the tokens, one line at a time.  If any authorities are down, we have no current way to note that, but someday we will.
              List<String> tokenList = new ArrayList<String>();
              while (true)
              {
                String line = br.readLine();
                if (line == null)
                  break;
                if (line.startsWith("TOKEN:"))
                {
                  tokenList.add(line.substring("TOKEN:".length()));
                  log.info(line);
                }
                else {
                  // It probably says something about the state of the authority(s) involved, so log it
                  log.info("Saw authority response "+line);
                }
              }
              return tokenList;
            }
            finally
            {
              br.close();
            }
          }
          finally
          {
            r.close();
          }
        }
        finally
        {
          is.close();
        }
      }
      finally
      {
        method.abort();
      }
    }
    catch (IOException e)
    {
      throw new MCFAuthorizerException("IO exception: "+e.getMessage(),e);
    }
  }

}
