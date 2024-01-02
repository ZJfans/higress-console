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

import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Arrays;

import javax.annotation.Resource;
import javax.crypto.Cipher;

import org.apache.commons.collections4.CollectionUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.alibaba.higress.sdk.constant.KubernetesConstants;
import com.alibaba.higress.sdk.exception.BusinessException;
import com.alibaba.higress.sdk.exception.ResourceConflictException;
import com.alibaba.higress.sdk.model.CommonPageQuery;
import com.alibaba.higress.sdk.model.PaginatedResult;
import com.alibaba.higress.sdk.model.TlsCertificate;
import com.alibaba.higress.sdk.service.kubernetes.KubernetesClientService;
import com.alibaba.higress.sdk.service.kubernetes.KubernetesModelConverter;

import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1Secret;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

@Service
public class TlsCertificateServiceImpl implements TlsCertificateService {

    private KubernetesClientService kubernetesClientService;
    private KubernetesModelConverter kubernetesModelConverter;

    private byte[] generateRandomData(int length) {
        byte[] data = new byte[length];
        new java.util.Random().nextBytes(data);
        return data;
    }

    private byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private byte[] decrypt(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    private static X509Certificate getCertificateFromPem(String certificate) throws Exception {
        try (PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8))))){
            PemObject pemObject = pemReader.readPemObject();
            byte[] certBytes = pemObject.getContent();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificateObj = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
            return certificateObj;
        }
    }

    private static PrivateKey getPrivateKeyFromPem(String privateKeyPem) throws Exception {
        try (PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateKeyPem.getBytes(StandardCharsets.UTF_8))))){
            PemObject pemObject = pemReader.readPemObject();
            byte[] decodedPrivateKeyBytes = pemObject.getContent();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPrivateKeyBytes);
            return keyFactory.generatePrivate(keySpec);
        }
    }

    @Resource
    public void setKubernetesClientService(KubernetesClientService kubernetesClientService) {
        this.kubernetesClientService = kubernetesClientService;
    }

    @Resource
    public void setKubernetesModelConverter(KubernetesModelConverter kubernetesModelConverter) {
        this.kubernetesModelConverter = kubernetesModelConverter;
    }

    @Override
    public PaginatedResult<TlsCertificate> list(CommonPageQuery query) {
        List<V1Secret> secrets;
        try {
            secrets = kubernetesClientService.listSecret(KubernetesConstants.SECRET_TYPE_TLS);
        } catch (ApiException e) {
            throw new BusinessException("Error occurs when listing Secret.", e);
        }
        if (CollectionUtils.isEmpty(secrets)) {
            return PaginatedResult.createFromFullList(Collections.emptyList(), query);
        }
        return PaginatedResult.createFromFullList(secrets, query, kubernetesModelConverter::secret2TlsCertificate);
    }

    @Override
    public TlsCertificate query(String name) {
        V1Secret secret;
        try {
            secret = kubernetesClientService.readSecret(name);
        } catch (ApiException e) {
            throw new BusinessException("Error occurs when reading the Secret with name: " + name, e);
        }
        if (secret == null) {
            return null;
        }
        if (!KubernetesConstants.SECRET_TYPE_TLS.equals(secret.getType())) {
            return null;
        }
        return kubernetesModelConverter.secret2TlsCertificate(secret);
    }

    @Override
    public TlsCertificate add(TlsCertificate certificate) {
        V1Secret secret = kubernetesModelConverter.tlsCertificate2Secret(certificate);
        V1Secret newSecret;
        try {
            newSecret = kubernetesClientService.createSecret(secret);
        } catch (ApiException e) {
            if (e.getCode() == HttpStatus.CONFLICT.value()) {
                throw new ResourceConflictException();
            }
            throw new BusinessException("Error occurs when updating the secret generated by tls certificate with name: "
                + certificate.getName(), e);
        }
        return kubernetesModelConverter.secret2TlsCertificate(newSecret);
    }

    @Override
    public TlsCertificate update(TlsCertificate tlsCertificate) {
        V1Secret secret = kubernetesModelConverter.tlsCertificate2Secret(tlsCertificate);
        V1Secret newSecret;
        try {
            newSecret = kubernetesClientService.replaceSecret(secret);
        } catch (ApiException e) {
            if (e.getCode() == HttpStatus.CONFLICT.value()) {
                throw new ResourceConflictException();
            }
            throw new BusinessException("Error occurs when updating the secret generated by tls certificate with name: "
                + tlsCertificate.getName(), e);
        }
        return kubernetesModelConverter.secret2TlsCertificate(newSecret);
    }

    @Override
    public void delete(String name) {
        try {
            kubernetesClientService.deleteSecret(name);
        } catch (ApiException e) {
            throw new BusinessException("Error occurs when deleting secret with name: " + name, e);
        }
    }

    @Override
    public boolean validate(TlsCertificate tlsCertificate) {
        try {
            String certificate = tlsCertificate.getCert();
            String privateKeyObj = tlsCertificate.getKey();
            X509Certificate certificateObj = getCertificateFromPem(certificate);
            PublicKey publicKey = certificateObj.getPublicKey();
            PrivateKey privateKey = getPrivateKeyFromPem(privateKeyObj);
            byte[] testData = generateRandomData(16);
            byte[] encryptedData = encrypt(publicKey, testData);
            byte[] decryptedData = decrypt(privateKey, encryptedData);
        } catch (Exception e) {
            throw new BusinessException("Error occurs when validate Certificate and private key with name: "
                + tlsCertificate.getName(), e);
        }
        return Arrays.equals(testData, decryptedData);
    }
}
