Installation instructions
------------ 

Install ansible galaxy collections and python dependencies:
 
```shell
  ansible-galaxy collection install yoctoalex.xc_cloud_modules
  ansible-galaxy collection install kubernetes.core
  pip3 install kubernetes
```

Create API Token. Navigate to the **Administration** page.
  
![navigate_to_administration](../assets/token_navigate.png)
  
Then open **Credentials** tab and click **Add Credentials**
  
![create_token](../assets/token_create_0.png)

Fill details and click **Generate** button
    
![fill_details](../assets/token_create_1.png)

Copy generated token to the ansible script in the evironments section. 
Here you can also configure your domain, namespace, tenant, app prefix, etc.

The solution contains two configurations:
- **waap-cdn-https.yaml** for HTTPS with Auto Cert
- **waap-cdn-http.yaml** for HTTP
    
Both configuration support [F5 Distributed Cloud Domain Delegation](https://docs.cloud.f5.com/docs/how-to/app-networking/domain-delegation). To enable set **dns_volterra_managed** to **True**. 

```yaml
  environment:
      XC_API_TOKEN: "your_api_token"
      XC_TENANT: "console.ves.volterra.io"
      
  vars:
      namespace: "cdn-demo-guide"
      prefix: ""
      domain: "your_domain.example.com"
      dns_volterra_managed: False
```

Execute ansible script with following command:

```shell
  ansible-playbook waap-cdn-http.yaml -i ./hosts
```

Check the output and create corresponding CNAME records on your DNS server. You can also find created Endpoints to access the website.

![ansible_output](../assets/ansible_output.png)
