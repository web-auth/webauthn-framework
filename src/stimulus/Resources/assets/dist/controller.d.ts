import { Controller } from '@hotwired/stimulus';
export default class extends Controller {
    static values: {
        requestResultUrl: {
            type: StringConstructor;
            default: string;
        };
        requestOptionsUrl: {
            type: StringConstructor;
            default: string;
        };
        requestSuccessRedirectUri: StringConstructor;
        creationResultUrl: {
            type: StringConstructor;
            default: string;
        };
        creationOptionsUrl: {
            type: StringConstructor;
            default: string;
        };
        creationSuccessRedirectUri: StringConstructor;
        usernameField: {
            type: StringConstructor;
            default: string;
        };
        displayNameField: {
            type: StringConstructor;
            default: string;
        };
        attestationField: {
            type: StringConstructor;
            default: string;
        };
        userVerificationField: {
            type: StringConstructor;
            default: string;
        };
        residentKeyField: {
            type: StringConstructor;
            default: string;
        };
        requireResidentKeyField: {
            type: StringConstructor;
            default: string;
        };
        authenticatorAttachmentField: {
            type: StringConstructor;
            default: string;
        };
        useBrowserAutofill: {
            type: BooleanConstructor;
            default: boolean;
        };
    };
    readonly requestResultUrlValue: string;
    readonly requestOptionsUrlValue: string;
    readonly requestSuccessRedirectUriValue?: string;
    readonly creationResultUrlValue: string;
    readonly creationOptionsUrlValue: string;
    readonly creationSuccessRedirectUriValue?: string;
    readonly usernameFieldValue: string;
    readonly displayNameFieldValue: string;
    readonly attestationFieldValue: string;
    readonly userVerificationFieldValue: string;
    readonly residentKeyFieldValue: string;
    readonly requireResidentKeyFieldValue: string;
    readonly authenticatorAttachmentFieldValue: string;
    readonly useBrowserAutofillValue: boolean;
    connect(): void;
    signin(event: Event): Promise<void>;
    signup(event: Event): Promise<void>;
    _dispatchEvent(name: string, payload: any): void;
    fetch(method: string, url: string, body: string): Promise<XMLHttpRequest>;
    _getData(): any;
}
