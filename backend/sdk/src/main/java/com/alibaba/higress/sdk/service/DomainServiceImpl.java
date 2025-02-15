/*
 * Copyright (c) 2022-2023 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.alibaba.higress.sdk.service;

import java.util.List;
import java.util.Optional;

import javax.annotation.Resource;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;

import com.alibaba.higress.sdk.constant.CommonKey;
import com.alibaba.higress.sdk.exception.BusinessException;
import com.alibaba.higress.sdk.exception.ResourceConflictException;
import com.alibaba.higress.sdk.model.CommonPageQuery;
import com.alibaba.higress.sdk.model.Domain;
import com.alibaba.higress.sdk.model.PaginatedResult;
import com.alibaba.higress.sdk.model.Route;
import com.alibaba.higress.sdk.model.RoutePageQuery;
import com.alibaba.higress.sdk.model.WasmPluginInstanceScope;
import com.alibaba.higress.sdk.service.kubernetes.KubernetesClientService;
import com.alibaba.higress.sdk.service.kubernetes.KubernetesModelConverter;
import com.alibaba.higress.sdk.service.kubernetes.KubernetesUtil;

import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1ConfigMap;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@org.springframework.stereotype.Service
public class DomainServiceImpl implements DomainService {

    @Resource
    private KubernetesClientService kubernetesClientService;

    @Resource
    private KubernetesModelConverter kubernetesModelConverter;

    @Resource
    private RouteService routeService;

    @Resource
    private WasmPluginInstanceService wasmPluginInstanceService;

    @Override
    public Domain add(Domain domain) {
        V1ConfigMap domainConfigMap = kubernetesModelConverter.domain2ConfigMap(domain);
        V1ConfigMap newDomainConfigMap;
        try {
            newDomainConfigMap = kubernetesClientService.createConfigMap(domainConfigMap);
        } catch (ApiException e) {
            if (e.getCode() == HttpStatus.CONFLICT.value()) {
                throw new ResourceConflictException();
            }
            throw new BusinessException("Error occurs when adding a new domain.", e);
        }
        return kubernetesModelConverter.configMap2Domain(newDomainConfigMap);
    }

    @Override
    public PaginatedResult<Domain> list(CommonPageQuery query) {
        List<V1ConfigMap> configMaps;
        try {
            configMaps = kubernetesClientService.listConfigMap();
        } catch (ApiException e) {
            throw new BusinessException("Error occurs when listing ConfigMap.", e);
        }
        List<V1ConfigMap> domainConfigMaps = configMaps.stream()
            .filter(cm -> StringUtils.startsWith(KubernetesUtil.getObjectName(cm), CommonKey.DOMAIN_PREFIX)).toList();
        return PaginatedResult.createFromFullList(domainConfigMaps, query, kubernetesModelConverter::configMap2Domain);
    }

    @Override
    public Domain query(String domainName) {
        V1ConfigMap configMap;
        String normalizedDomainName = kubernetesModelConverter.domainName2ConfigMapName(domainName);
        try {
            configMap = kubernetesClientService.readConfigMap(normalizedDomainName);
        } catch (ApiException e) {
            throw new BusinessException("Error occurs when reading the ConfigMap with name: " + normalizedDomainName,
                e);
        }
        return Optional.ofNullable(configMap).map(kubernetesModelConverter::configMap2Domain).orElse(null);
    }

    @Override
    public void delete(String domainName) {
        PaginatedResult<Route> routes = routeService.list(new RoutePageQuery(domainName));
        if (CollectionUtils.isNotEmpty(routes.getData())) {
            throw new IllegalArgumentException("The domain has routes. Please delete them first.");
        }

        String configMapName = kubernetesModelConverter.domainName2ConfigMapName(domainName);
        try {
            kubernetesClientService.deleteConfigMap(configMapName);
        } catch (ApiException e) {
            throw new BusinessException("Error occurs when deleting the ConfigMap with name: " + configMapName, e);
        }

        wasmPluginInstanceService.deleteAll(WasmPluginInstanceScope.DOMAIN, domainName);
    }

    @Override
    public Domain put(Domain domain) {
        V1ConfigMap domainConfigMap = kubernetesModelConverter.domain2ConfigMap(domain);
        V1ConfigMap updatedConfigMap;
        try {
            updatedConfigMap = kubernetesClientService.replaceConfigMap(domainConfigMap);
        } catch (ApiException e) {
            if (e.getCode() == HttpStatus.CONFLICT.value()) {
                throw new ResourceConflictException();
            }
            throw new BusinessException(
                "Error occurs when replacing the ConfigMap generated by domain: " + domain.getName(), e);
        }

        PaginatedResult<Route> routes = routeService.list(new RoutePageQuery(domain.getName()));
        if (CollectionUtils.isNotEmpty(routes.getData())) {
            routes.getData().forEach(routeService::update);
        }

        return kubernetesModelConverter.configMap2Domain(updatedConfigMap);
    }
}