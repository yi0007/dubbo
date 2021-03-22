/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.metadata.report;


import org.apache.dubbo.common.URL;
import org.apache.dubbo.metadata.MappingListener;
import org.apache.dubbo.metadata.MetadataInfo;
import org.apache.dubbo.metadata.definition.model.ServiceDefinition;
import org.apache.dubbo.metadata.report.identifier.MetadataIdentifier;
import org.apache.dubbo.metadata.report.identifier.ServiceMetadataIdentifier;
import org.apache.dubbo.metadata.report.identifier.SubscriberMetadataIdentifier;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 从接口可以看出，这个类的实现类主要存储的是 ：
 * Provider暴露的接口服务的URL信息
 * Consumer订阅的接口服务的URL信息
 * 接口的定义信息
 * 对于不同的元数据注册中心，会有不同的实现
 */
public interface MetadataReport {
    /**
     * Service Definition -- START
     **/
    void storeProviderMetadata(MetadataIdentifier providerMetadataIdentifier, ServiceDefinition serviceDefinition);

    String getServiceDefinition(MetadataIdentifier metadataIdentifier);

    /**
     * Application Metadata -- START
     **/
    default void publishAppMetadata(SubscriberMetadataIdentifier identifier, MetadataInfo metadataInfo) {
    }

    default MetadataInfo getAppMetadata(SubscriberMetadataIdentifier identifier, Map<String, String> instanceMetadata) {
        return null;
    }

    /**
     * Service<-->Application Mapping -- START
     **/
    default Set<String> getServiceAppMapping(String serviceKey, MappingListener listener, URL url) {
        return Collections.emptySet();
    }

    default void registerServiceAppMapping(String serviceKey, String application, URL url) {
        return;
    }

    /**
     * deprecated or need triage
     **/
    void storeConsumerMetadata(MetadataIdentifier consumerMetadataIdentifier, Map<String, String> serviceParameterMap);

    List<String> getExportedURLs(ServiceMetadataIdentifier metadataIdentifier);

    void saveServiceMetadata(ServiceMetadataIdentifier metadataIdentifier, URL url);

    void removeServiceMetadata(ServiceMetadataIdentifier metadataIdentifier);

    void saveSubscribedData(SubscriberMetadataIdentifier subscriberMetadataIdentifier, Set<String> urls);

    List<String> getSubscribedURLs(SubscriberMetadataIdentifier subscriberMetadataIdentifier);

}
