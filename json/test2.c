#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "arraylist.h"

/*****************************************************************************/

void controller_get_devices(
    struct json_object *request, struct json_object *response)
{
    json_object_object_add(response, "result", json_object_new_string("controller_get_devices"));
}

/*****************************************************************************/

void controller_get_device_info(
    struct json_object *request, struct json_object *response)
{
    json_object_object_add(response, "result", json_object_new_string("controller_get_device_info"));
}

/*****************************************************************************/

void controller_set_device_info(
    struct json_object *request, struct json_object *response)
{
    json_object_object_add(response, "result", json_object_new_string("controller_set_device_info"));
}

/*****************************************************************************/

void controller_set_device(
    struct json_object *request, struct json_object *response)
{
    json_object_object_add(response, "result", json_object_new_string("controller_set_device"));
}

/*****************************************************************************/

void controller_get_events(
    struct json_object *request, struct json_object *response)
{
    json_object_object_add(response, "result", json_object_new_string("controller_get_events"));
}

/*****************************************************************************/


void jsonrpc_system_list_methods(
    struct json_object *request, struct json_object *response)
{
    struct json_object *methods = json_object_new_array();
    json_object_array_add(methods, json_object_new_string("contoller.getDevices"));
    json_object_array_add(methods, json_object_new_string("contoller.getDeviceInfo"));
    json_object_array_add(methods, json_object_new_string("contoller.setDeviceInfo"));
    json_object_array_add(methods, json_object_new_string("contoller.setDevice"));
    json_object_array_add(methods, json_object_new_string("contoller.getEvents"));
    json_object_object_add(response, "result", methods);
}


/*****************************************************************************/

char* jsonrpc_request_method(struct json_object *request)
{
    struct json_object *value;
    value = json_object_object_get(request, "method");
    return json_object_get_string(value);
}

/*****************************************************************************/

void jsonrpc_service(struct json_object *request, struct json_object *response)
{
    char *method = jsonrpc_request_method(request);
    
    printf("method=%s.\n", method);
    
    if(strcmp(method, "system.listMethods") == 0)
    {
       jsonrpc_system_list_methods(request, response);
    }
    else if(strcmp(method, "controller.getDevices") == 0)
    {
       controller_get_devices(request, response);
    }
    else if(strcmp(method, "controller.getDeviceInfo") == 0)
    {
       controller_get_device_info(request, response);
    }
    else if(strcmp(method, "controller.setDeviceInfo") == 0)
    {
       controller_set_device_info(request, response);
    }
    else if(strcmp(method, "controller.setDevice") == 0)
    {
       controller_set_device(request, response);
    }
    else if(strcmp(method, "controller.getEvents") == 0)
    {
       controller_get_events(request, response);
    }
    
} 

/*****************************************************************************/

char* jsonrpc_process(char* request_text)
{
    char* response_text;
    struct json_object *request;
    struct json_object *response;

    request = json_tokener_parse(request_text);
    response = json_object_new_object();

    jsonrpc_service(request, response);
    
    response_text = json_object_to_json_string(response);
    printf("response_text=%s\n", response_text);

    json_object_put(request);
    json_object_put(response);
    
    return response_text;
}

/*****************************************************************************/

int main(int argc, char **argv)
{
    char* request1 = "{\"method\": \"system.listMethods\", \"params\": []}";
    mc_set_debug(1);
    
    char* response1 = jsonrpc_process(request1);
    printf("response=%s\n", response1);
    
    return 0;
}

/*****************************************************************************/
